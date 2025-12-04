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

constexpr int WORKER_THREADS = 0;   // we can use our custom number of worker threads

enum class OperationType : uint32_t {
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