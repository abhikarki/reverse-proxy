#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h> // required for AcceptEx()
#include <iostream>
#include <string>
#include <vector>
#include <atomic>
#include <memory>
#include <cassert>
#include <algorithm>
#include <thread>

// #pragma comment(lib, "Ws2_32.lib");

constexpr unsigned short LISTEN_PORT = 8080;
constexpr int WORKER_THREADS = 0;	// we can use our custom number of worker threads here
constexpr int BUF_SIZE = 16 * 1024; // 16 KB
constexpr int BACKLOG = 128;
// number of bytes for addresses (IPV4). AcceptEx documentation says buffer size parameters must be at least 16 bytes greater than
// size of address structure for the transport protocol in use
constexpr int ACCEPT_ADDR_LEN = sizeof(sockaddr_in) + 16;

enum class OpType : uint32_t
{
	READ = 1,
	WRITE = 2,
	ACCEPT = 3
};

struct PER_SOCKET_CONTEXT
{
	SOCKET socket;
	std::atomic<bool> closing;
	std::atomic<int> pendingIO;
	// Constructor, allow uninitialized socket and set closing to false (client connection active)
	PER_SOCKET_CONTEXT(SOCKET s = INVALID_SOCKET) : socket(s), closing(false), pendingIO(0) {}
};

void print_wsa_error(const char *msg)
{
	int err = WSAGetLastError();
	std::cerr << msg << " WSAGetLastError = " << err << "\n";
}

struct PER_IO_OPERATION_DATA
{
	OVERLAPPED overlapped;
	WSABUF wsaBuf;
	char *buffer;
	OpType opType;
	DWORD flags;
	SOCKET acceptSocket; // for opType == Accept
	// Constructor
	PER_IO_OPERATION_DATA(OpType t = OpType::READ) : buffer(nullptr), opType(t), flags(0), acceptSocket(INVALID_SOCKET)
	{
		// set all members of overlapped to zero
		ZeroMemory(&overlapped, sizeof(overlapped));
		wsaBuf.buf = nullptr;
		wsaBuf.len = 0;
	}
	// Destructor
	~PER_IO_OPERATION_DATA()
	{
		if (buffer)
		{
			delete[] buffer;
			buffer = nullptr;
		}

		if (acceptSocket != INVALID_SOCKET)
		{
			closesocket(acceptSocket);
			acceptSocket = INVALID_SOCKET;
		}
	}
};

// pointer to the extension function AcceptEx(), PASCAL calling convention (callee stack cleanup, left-to-right push)
typedef BOOL(PASCAL *LPFN_ACCEPTEX)(
	SOCKET sListenSocket,
	SOCKET sAcceptSocket,
	PVOID lpOutputBuffer,
	DWORD dwReceiveDataLength,
	DWORD dwLocalAddressLength,
	DWORD dwRemoteAddressLength,
	LPDWORD lpdwBytesReceived,
	LPOVERLAPPED lpOverlapped);

LPFN_ACCEPTEX g_AcceptEx = nullptr;
SOCKET g_listenSocket = INVALID_SOCKET;

PER_IO_OPERATION_DATA *post_recv(PER_SOCKET_CONTEXT *sockCtx)
{
	auto *ioData = new PER_IO_OPERATION_DATA(OpType::READ);
	ioData->buffer = new char[BUF_SIZE];
	ioData->wsaBuf.buf = ioData->buffer;
	ioData->wsaBuf.len = BUF_SIZE;
	ioData->flags = 0;
	ZeroMemory(&ioData->overlapped, sizeof(ioData->overlapped));

	sockCtx->pendingIO.fetch_add(1, std::memory_order_relaxed);

	DWORD bytesReceived = 0;
	int rc = WSARecv(
		sockCtx->socket,
		&ioData->wsaBuf,
		1,
		&bytesReceived,
		&ioData->flags,
		&ioData->overlapped, // this makes it asynchronous and return immediately
		nullptr);

	if (rc == SOCKET_ERROR)
	{
		int err = WSAGetLastError();
		if (err != WSA_IO_PENDING)
		{
			sockCtx->pendingIO.fetch_sub(1, std::memory_order_relaxed);
			print_wsa_error("WSARecv failed");
			delete ioData;
			return nullptr;
		}
	}
	// successfully posted receive
	return ioData;
}

PER_IO_OPERATION_DATA *post_send(PER_SOCKET_CONTEXT *sockCtx, const char *data, DWORD len)
{
	auto *ioData = new PER_IO_OPERATION_DATA(OpType::WRITE);
	ioData->buffer = new char[len];
	memcpy(ioData->buffer, data, len);
	ioData->wsaBuf.buf = ioData->buffer;
	ioData->wsaBuf.len = len;
	ZeroMemory(&ioData->overlapped, sizeof(ioData->overlapped));

	sockCtx->pendingIO.fetch_add(1, std::memory_order_relaxed);

	DWORD bytesSent = 0;
	int rc = WSASend(
		sockCtx->socket,
		&ioData->wsaBuf,
		1,
		&bytesSent,
		0,
		&ioData->overlapped, // if overlapped was nullptr this would be blocking
		nullptr);

	// if SOCKET_ERROR, then it could be WSA_IO_PENDING which is asynchronous but okay
	if (rc == SOCKET_ERROR)
	{
		int err = WSAGetLastError();
		if (err != WSA_IO_PENDING)
		{
			// failed immediately so we undo the increment as well
			sockCtx->pendingIO.fetch_sub(1, std::memory_order_relaxed);
			print_wsa_error("WSASend failed");
			delete ioData;
			return nullptr;
		}
	}
	return ioData;
}

//
PER_IO_OPERATION_DATA *post_accept(HANDLE iocp)
{
	// the pointer to the AcceptEx function needs to be initialized
	if (!g_AcceptEx)
		return nullptr;

	auto *ioData = new PER_IO_OPERATION_DATA(OpType::ACCEPT);

	ioData->buffer = new char[(ACCEPT_ADDR_LEN) * 2];
	ioData->wsaBuf.buf = ioData->buffer;
	ioData->wsaBuf.len = (ACCEPT_ADDR_LEN) * 2;

	SOCKET acceptSock = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
	if (acceptSock == INVALID_SOCKET)
	{
		print_wsa_error("WSASocket for accept failed");
		delete ioData;
		return nullptr;
	}
	ioData->acceptSocket = acceptSock;

	DWORD bytesReceived = 0;
	BOOL ok = g_AcceptEx(
		g_listenSocket,
		acceptSock,
		ioData->buffer,
		0,
		ACCEPT_ADDR_LEN,
		ACCEPT_ADDR_LEN,
		&bytesReceived,
		&ioData->overlapped);

	if (!ok)
	{
		int err = WSAGetLastError();
		if (err != ERROR_IO_PENDING && err != WSA_IO_PENDING)
		{
			// this means that immediate failure occurred.
			print_wsa_error("AcceptEx failed");
			closesocket(acceptSock);
			delete ioData;
			return nullptr;
		}
	}
	// so we posted AcceptEx and the completion will be notified by the IOCP
	// acceptSock will be associated with the iocp handle later when we receive a client connection.
	return ioData;
}

// when successful g_AcceptEx contains the pointer to the AcceptEx() function
bool init_acceptex(SOCKET listenSock)
{
	g_listenSocket = listenSock;
	GUID guidAcceptEx = WSAID_ACCEPTEX; // Globally Unique Identifier for AcceptEx()
	DWORD bytes = 0;
	int rc = WSAIoctl(
		listenSock,
		SIO_GET_EXTENSION_FUNCTION_POINTER, // control code to specify the task
		&guidAcceptEx,
		sizeof(guidAcceptEx),
		&g_AcceptEx,
		sizeof(g_AcceptEx),
		&bytes,
		nullptr,
		nullptr);

	if (rc == SOCKET_ERROR)
	{
		print_wsa_error("WSAIoctl failed, failed to get the function pointer");
		return false;
	}
	return true;
}

void safeClose(PER_SOCKET_CONTEXT *ctx)
{
	if (ctx->socket != INVALID_SOCKET)
	{
		shutdown(ctx->socket, SD_BOTH);
		closesocket(ctx->socket);
		ctx->socket = INVALID_SOCKET;
	}
	delete ctx;
}

int main(int argc, char *argv[])
{
	// Initializing winsock.
	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD(2, 2);
	int wsaerr = WSAStartup(wVersionRequested, &wsaData);
	if (wsaerr != 0)
	{
		std::cout << "Winsock dll not found" << std::endl;
		return 0;
	}
	else
	{
		std::cout << "Winsock dll initialized" << std::endl;
		std::cout << "Status: " << wsaData.szSystemStatus << std::endl;
	}

	// Initializing a listening socket.
	SOCKET listenSocket = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
	if (listenSocket == INVALID_SOCKET)
	{
		std::cout << "Error creating listening socket" << WSAGetLastError() << std::endl;
		WSACleanup();
		return 0;
	}
	else
	{
		std::cout << "socket (unbounded) setup success" << std::endl;
	}

	// allow for resuse immediately without the general 2MSL TIME_WAIT, bypass the TIME_WAIT protection
	BOOL reuse = TRUE;
	if (setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse)) == SOCKET_ERROR)
	{
		print_wsa_error("setsockopt(SO_REUSEADDR failed");
	}

	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(LISTEN_PORT);

	if (bind(listenSocket, (sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
	{
		print_wsa_error("bind failed");
		closesocket(listenSocket);
		WSACleanup();
		return 1;
	}

	if (listen(listenSocket, BACKLOG) == SOCKET_ERROR)
	{
		print_wsa_error("listen failed");
		closesocket(listenSocket);
		WSACleanup();
		return 1;
	}

	// if no error occurred, and the listen socket is successfully bound
	std::cout << "Listening on port " << LISTEN_PORT << std::endl;

	// creating IOCP
	HANDLE iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);
	if (!iocp)
	{
		print_wsa_error("Creating IOCP failed");
		closesocket(listenSocket);
		WSACleanup();
		return 1;
	}

	// associating listen socket with iocp since it will post completion related to the accepted connections
	CreateIoCompletionPort((HANDLE)listenSocket, iocp, 0, 0);

	if (!init_acceptex(listenSocket))
	{
		closesocket(listenSocket);
		WSACleanup();
		return 1;
	}

	// creating worker thread pool
	unsigned int cpuCount = std::max(1u, static_cast<unsigned int>(std::thread::hardware_concurrency()));
	unsigned int numWorkers = (WORKER_THREADS > 0) ? WORKER_THREADS : (cpuCount * 2);
	std::atomic<bool> running{true}; // atomic bool for thread safety and race condition, also guarantees no reorder of memory operations
	std::vector<std::thread> workers;
	workers.reserve(numWorkers);

	std::cout << "Starting " << numWorkers << " worker threads" << std::endl;
	std::cout.flush();

	for (unsigned int i = 0; i < numWorkers; i++)
	{
		workers.emplace_back([iocp, &running]()
							 {
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
				);

				// take the raw bytes in the completionKey and turn it back to a socket context
				PER_SOCKET_CONTEXT* sockCtx = reinterpret_cast<PER_SOCKET_CONTEXT*>(completionKey);
				
				// the overlapped is the first member, so we can take it as the start of the PER_IO_OPERATION_DATA
				PER_IO_OPERATION_DATA* ioData = reinterpret_cast<PER_IO_OPERATION_DATA*>(overlapped);

				if(!ioData){
					continue;
				}
				// checking the result for the GetQueuedCompletionStatus
				if (!ok) {
					DWORD err = GetLastError();
					if (overlapped == nullptr) {
						// could be the condition that the main thread wanted to wake up this worker thread to signal stop
						// so we break out of the loop

						if (!running.load()) break;
						// if not, log the warning and continue the next iteration of the while loop
						std::cerr << "Failed with no overlapped: " << err << std::endl;
						continue;
					}
					else {
						if(ioData->opType == OpType::READ || ioData->opType == OpType::WRITE){
							if(sockCtx){
								int remain = sockCtx->pendingIO.fetch_sub(1) - 1;
								if(remain == 0 && sockCtx->closing.load()) safeClose(sockCtx);
							}
						}
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

				if(ioData->opType == OpType::ACCEPT){
					SOCKET accepted = ioData->acceptSocket;
					DWORD dwErr = 0;

					if(accepted != INVALID_SOCKET){
						int rc = setsockopt(accepted, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char*)&g_listenSocket, sizeof(g_listenSocket));
						if(rc == SOCKET_ERROR){
							print_wsa_error("SO_UPDATE_ACCEPT_CONTEXT_FAILED");
							closesocket(accepted);
							delete ioData;

							PER_IO_OPERATION_DATA* next = post_accept(iocp);
							if(next){
								// Since we donot have a mutex to protect pendingAccepts vector, we cannot push_back this pending accept
								// to the vector since this can create a race condition. so, we will skip this for now and let kernel handle
								// the cleanup of pending accepts when shutting down.
							}
							continue;
						}

						PER_SOCKET_CONTEXT* sockCtx = new PER_SOCKET_CONTEXT(accepted);
						if(!CreateIoCompletionPort((HANDLE)accepted, iocp, (ULONG_PTR)sockCtx, 0)){
							print_wsa_error("associating the accept socket with iocp failed");
							closesocket(accepted);
							delete sockCtx;
							delete ioData;
							PER_IO_OPERATION_DATA* next = post_accept(iocp);
							if(next) {
								// same as before, skip since no mutex on the pending accepts vector
							}
							continue;
						}

						// initiate first receive on the new socket
						PER_IO_OPERATION_DATA* recvOp = post_recv(sockCtx);
						if(!recvOp){
							std::cerr << "Failed to post initial receive for the accepted socket" << std::endl;
							if(!sockCtx->closing.exchange(true)){
								closesocket(sockCtx->socket);
								delete sockCtx;
							}
						}
						
						// Prevent the destructor from closing the socket we just handed off
						ioData->acceptSocket = INVALID_SOCKET;
					}

					delete ioData;
					// post another accept
					PER_IO_OPERATION_DATA* nextAccept = post_accept(iocp);
					if(nextAccept){
						// we can track by pushing it to the pending vector if it is mutex
					}
					continue;
				}


				// if bytesTransferred 0 and operation is read, it means the client closed connection on sending end.
				// Here, we close the socket operations, deallocate memory
				if (bytesTransferred == 0 && ioData->opType == OpType::READ) {
					std::cout << "client disconnected" << std::endl;
					// signal closing. .exhchange changes the atomic variable and returns prev value
					if (!sockCtx->closing.exchange(true)) {
						CancelIoEx((HANDLE)sockCtx->socket, NULL);
					}
					delete ioData;
					continue;
				}

				if (ioData->opType == OpType::READ) {
					std::cout << "Read " << bytesTransferred << " bytes from client" << std::endl;

					// non blocking, see the implementation as top.
					post_send(sockCtx, ioData->buffer, bytesTransferred);
					
					int remain = sockCtx->pendingIO.fetch_sub(1) - 1;  //fetch sub return previous value
					if(remain == 0 && sockCtx->closing.load()){
						safeClose(sockCtx);
					}
					// another receive, this is non blocking
					PER_IO_OPERATION_DATA* nextRecv = post_recv(sockCtx);
					if (!nextRecv) {
						std::cerr << "Failed to post receive, closing client." << std::endl;
						if(!sockCtx->closing.exchange(true)){
							CancelIoEx((HANDLE)sockCtx->socket, NULL);
						}
					}
					delete ioData;
				}
				else if (ioData->opType == OpType::WRITE) {
					std::cout << "Write complete: " << bytesTransferred << std::endl;
					int remain = sockCtx->pendingIO.fetch_sub(1) - 1;
					if(remain == 0 && sockCtx -> closing.load()){
						safeClose(sockCtx);
					}
					delete ioData;
				}
				else {
					std::cerr << "Unknown OpType" << std::endl;
					delete ioData;
				}

			} });
	}

	// Post initial accepts AFTER worker threads are created
	int initial_accepts = std::max(4, (int)numWorkers);
	std::vector<PER_IO_OPERATION_DATA *> pendingAccepts;
	pendingAccepts.reserve(initial_accepts);
	for (int i = 0; i < initial_accepts; i++)
	{
		PER_IO_OPERATION_DATA *acceptData = post_accept(iocp);
		if (acceptData)
			pendingAccepts.push_back(acceptData);
	}

	std::cout << "Press any key to stop server: ";
	std::cin.get();
	std::cout << "Shutting down...";

	running.store(false);

	closesocket(listenSocket);

	// closing

	// post completion to wakeup worker threads.
	for (size_t i = 0; i < workers.size(); i++)
	{
		PostQueuedCompletionStatus(iocp, 0, 0, nullptr);
	}

	// wait for the threads to complete
	for (auto &t : workers)
	{
		if (t.joinable())
			t.join();
	}

	// pendingAccepts cleanup
	for (PER_IO_OPERATION_DATA *ioData : pendingAccepts)
	{
		if (ioData != nullptr)
		{
			delete ioData;
		}
	}

	CloseHandle(iocp);
	WSACleanup();
	std::cout << "Server stopped successfully" << std::endl;
	return 0;
}