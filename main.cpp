#include "stdafx.h"
#include <winsock2.h>
#include <ws2tcpip.h>

#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <memory>
#include <cassert>


#pragma comment(lib, "Ws2_32.lib");

constexpr unsigned short LISTEN_PORT = 8080;
constexpr int WORKER_THREADS = 0;   // we can use our custom number of worker threads here
constexpr int BUF_SIZE = 16 * 1024  // 16 KB

enum class OpType : uint32_t {
	READ = 1,
	WRITE = 2
};

struct PER_SOCKET_CONTEXT {
	SOCKET socket;
	std::atomic<bool> closing;
	// Constructor, allow uninitialized socket and set closing to false (client connection active)
	PER_SOCKET_CONTEXT(SOCKET s = INVALID_SOCKET) : socket(s), closing(false) {}
};

void print_wsa_error(const char* msg) {
	int err = WSAGetLastError();
	std::cerr << msg << " WSAGetLastError = " << err "\n";
}


struct PER_IO_OPERATION_DATA {
	OVERLAPPED overlapped;
	WSABUF wsaBuf;
	char* buffer;
	OpType opType;
	DWORD flags;
	// Constructor
	PER_IO_OPERATION_DATA(OpType t = OpType::READ) : buffer(nullptr), opType(t), flags(0) {
		// set all members of overlapped to zero
		ZeroMemory(&overlapped, sizeof(overlapped));
		wsaBuf.buf = nullptr;
		wsaBuf.len = 0;
	}
	// Destructor
	~PER_IO_OPERATION_DATA() {
		if (buffer) {
			delete[] buffer;
			buffer = nullptr;
		}
	}
};

PER_IO_OPERATION_DATA* post_recv(PER_SOCKET_CONTEXT* sockCtx) {
	auto* ioData = new PER_IO_OPERATION_DATA(OpType::READ);
	ioData->buffer = new char[BUF_SIZE];
	ioData->wsaBuf.buf = ioData->buffer;
	ioData->wsaBuf.len = BUF_SIZE;
	ioData->flags = 0;
	ZeroMemory(&ioData->overlapped, sizeof(ioData->overlapped));

	DWORD bytesReceived = 0;
	int rc = WSARecv(
		sockCtx->socket,
		&ioData->wsaBuf,
		1,
		&bytesReceived,
		&ioData->flags,
		&ioData->overlapped,    // this makes it asynchronous and return immediately
		nullptr
	);

	if (rc == SOCKET_ERROR) {
		int err = WSAGetLastError();
		if (err != WSA_IO_PENDING) {
			print_wsa_error("WSARecv failed");
			delete ioData;
			return nullptr;
		}
	}
	// successfully posted receive
	return ioData;
}



PER_IO_OPERATION_DATA* post_send(PER_SOCKET_CONTEXT* sockCtx, const char* data, DWORD len) {
	auto* ioData = new PER_IO_OPERATION_DATA(OpType::WRITE);
	ioData->buffer = new char[len];
	memcpy(ioData->buffer, data, len);
	ioData->wsaBuf.buf = ioData->buffer;
	ioData->wsaBuf.len = len;
	ZeroMemory(&ioData->overlapped, sizeOf(ioData->overlapped));

	DWORD bytesSent = 0;
	int rc = WSASend(
		sockCtx->socket,
		&ioData->wsaBuf,
		1,
		&bytesSent,
		0,  
		nullptr            // overlapped is nullptr so this is blocking right now.
	);

	// if SOCKET_ERROR, then it could be WSA_IO_PENDING which is asynchronous but okay
	if (rc == SOCKET_ERROR) {
		int err = WSAGetLastError();
		if (err != WSA_IO_PENDING) {
			print_wsa_error("WSASend failed");
			delete ioData;
			return nullptr;
		}
	}
	return ioData;
}


int main(int argc, char *argv[]) {
	// Initializing winsock.
	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD(2, 2);
	int wsaerr = WSAStartup(wVersionRequested, &wsaData);
	if (wsaerr != 0) {
		std::cout << "Winsock dll not found" << std::endl;
		return 0;
	}
	else {
		std::cout << "Winsock dll initialized" << std::endl;
		std::cout << "Status: " << wsaData.szSystemStatus << std::endl;
	}
	
	// Initializing a listening socket.
	SOCKET listenSocket = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, 0);
	if (listenSocket == INVALID_SOCKET) {
		std::cout << "Error creating listening socket" << WSAGetLastError() << std::endl;
		WSACleanup();
		return 0;
	}
	else {
		std::cout << "socket (unbounded) setup success" << std::endl;
	}

	// allow for resuse immediately without the general 2MSL TIME_WAIT, bypass the TIME_WAIT protection
	BOOL reuse = TRUE;
	if (setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(resuse)) == SOCKET_ERROR) {
		print_wsa_error("setsockopt(SO_REUSEADDR failed");
	}

	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(LISTEN_PORT);

	if (bind(listenSocket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
		print_wsa_error("bind failed");
		closesocket(listenSocket);
		WSACleanup();
		return 1;
	}

	if (listen(listenSocket, BACKLOG) == SOCKET_ERROR) {
		print_wsa_error("listen failed");
		closeSocket("listen failed");
		WSACleanup();
		return 1;
	}

	// if no error occurred, and the listen socket is successfully bound
	std::cout << "Listening on port " << LISTEN_PORT << std::endl;

	// creating IOCP
	HANDLE iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);
	if (!iocp) {
		print_wsa_error("Creating IOCP failed");
		closesocket(listenSocket);
		WSACleanup();
		return 1;
	}

	// creating worker thread pool
	unsigned int cpuCount = std::max(1u, std::thread::hardware_concurrency());
	unsigned int numWorkers = (WORKER_THREADS > 0) ? WORKER_THREADS : (cpuCount * 2);
	std::atomic<bool> running{ true };   // atomic bool for thread safety and race condition, also guarantees no reorder of memory operations
	std::vector<std::thread> workers;
	workers.reserve(numWorkers);

	std::cout << "Starting " << numWorkers << " worker threads" << endl;

	for (unsigned int i = 0; i < numWorkers; i++) {
		workers.emplace_back([iocp, &running]()) {
			while (running.load()) {
				DWORD bytesTransferred = 0;
				ULONG_PTR completionKey = 0;
				LPOVERLAPPED overlapped = nullptr;

				// this is blocking and puts the thread to waiting
				BOOL ok = GetQueuedCompletionStatus(
					iocp,
					&bytesTransferred,
					&completionKey,
					&overlapped,
					INFINITE
				)

				// take the raw bytes in the completionKey and turn it back to a socket context
				PER_SOCKET_CONTEXT * sockCtx = reinterpret_cast<PER_SOCKET_CONTEXT*>(completionKey);
				
				// the overlapped is the first member, so we can take it as the start of the PER_IO_OPERATION_DATA
				PER_IO_OPERATION_DATA* ioData = reinterpret_cast<PER_IO_OPERATION_DATA*>(overlapped);

				// checking the result for the GetQueuedCompletionStatus
				if (!ok) {
					if (overlapped == nullptr) {
						// could be the condition that the main thread wanted to wake up this worker thread to signal stop
						// so we break out of the loop

						if (!running.load()) break;
						// if not, log the warning and continue the next iteration of the while loop
						std::cerr << "Failed with no overlapped: " << err << std::endl;
						continue;
					}
					else {
						// I/O operation failed, if cleanup thread deleted sockCtx, we will delete socket's pending operations' context
						if (ioData != nullptr) {
							delete ioData;
						}
					}
					// log error
					std::cerr << "I/O operation failed on socket, " << err << std::endl;
				}

				// in case the ok is true but the main thread might call PostQueuedCompletionStatus to signal stop
				if (overlapped == nullptr) {
					if (!running.load()) break;
					// else continue to next iteration.
					continue;
				}

				// final check before proceeding
				assert(sockCtx != nullPtr && ioData != nullptr);


				// if bytesTransferred 0 and operation is read, it means the client closed connection on sending end.
				// Here, we close the socket operations, deallocate memory
				if (bytesTransferred == 0 && ioData->opTpye == OpType::READ) {
					std::cout << "client disconnected" << std::endl;
					// signal closing. .exhchange changes the atomic variable and returns prev value
					if (!sockCtx->closing.exchange(true)) {
						closeSocket(sockCtx->socket);
						delete sockCtx;
					}
					delete ioData;
					continue;
				}

				if (ioData->opType == OpType::READ) {
					std::cout << "Read" << bytesTransferred << " bytes from client" << std:endl;

					// currently blocking, see the implementation as top.
					post_send(sockCtx, ioData->buffer, bytesTransferred);

					// another receive, this is non blocking unlike post_send
					PER_IO_OPERATION_DATA* nextRecv = post_recv(sockCtx);
					if (!nextRecv) {
						std::cerr << "Failed to post receive, closing client." << endl;
						if (!sockCtx->closing.exchange(true)) {
							closesocket(sockCtx->socket);
							delete sockCtx;
						}
					}
					delete ioData;
				}


			}
		}
	}





	sockaddr_in service;
	service.sin_family = AF_NET;
	InetPton(AF_NET, _T("127.0.0.1"), &service.sin_addr.s_addr);
	service.sin_port = htons(port);
	if (bind(serverSocket, (SOCKADDR*)&service, sizeof(service)) == SOCKET_ERROR) {
		std::cout << "socket binding failed: " << WSAGetLastError() << std::endl;
		closeSocket(serverSocket);
		WSACleanup();
		return 0;
	}
	else {
		std::cout << "Socket binding was successful" << std::endl;
	}

	// currently using backlog as 1 for simplicity.
	if (listen(serverSocket, 1) == SOCKET_ERROR) {
		std::cout << "Error on socket: " << WSAGetLastError() << std::endl;
	}
	else {
		std::cout << "Success: socket listening for connections." << std::endl;
	}

	// this is a blocking function
	acceptSocket = accept(serverSocket, NULL, NULL);
	if (acceptSocket == INVALID_SOCKET) {
		std::cout << "accept() failed: " << WSAGetLastError() << std::endl;
		WSACleanup();
		return -1;
	}
	std::cout << "connection accepted" << std::endl;
	system("pause");
	WSACleanup();

}