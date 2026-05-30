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
#include <sstream>
#include "proxy.h"
#include "tls/tls_context.h"
#include "tls/tls_connection.h"
#include "http_parser.h"
#include "load_balancer.h"
#include "upstream.h"

// #pragma comment(lib, "Ws2_32.lib");

constexpr unsigned short LISTEN_PORT = 8080;
constexpr int WORKER_THREADS = 0;	// we can use our custom number of worker threads here
constexpr int BUF_SIZE = 16 * 1024; // 16 KB
constexpr int BACKLOG = 128;
// number of bytes for addresses (IPV4). AcceptEx documentation says buffer size parameters must be at least 16 bytes greater than
// size of address structure for the transport protocol in use
constexpr int ACCEPT_ADDR_LEN = sizeof(sockaddr_in) + 16;
// initialize rate limiter 
RateLimit::Limiter g_rateLimiter(RateLimit::Config(100.0, 10.0, true));     // we need to disable this if testing with same IP address to prevent getting rate limited
// TLS context
TLS::Context g_tlsContext;

LoadBalance::LoadBalancer g_loadBalancer;

enum class OpType : uint32_t
{
	READ = 1,
	WRITE = 2,
	ACCEPT = 3,
	CONNECT_UPSTREAM = 4,
	READ_UPSTREAM = 5,
	WRITE_UPSTREAM = 6
};

struct PER_SOCKET_CONTEXT
{
	SOCKET socket;
	std::atomic<bool> closing;
	std::atomic<int> pendingIO;
	std::string clientIP; // for rate limiting

	std::unique_ptr<TLS::Connection> tlsConn;
	bool tlsEnabled;

	std::vector<char> tlsInputBuffer;
	std::vector<char> tlsOutputBuffer;
	std::vector<char> appDataBuffer;

	HTTP::Parser httpParser;
	bool isBackendConnection;
	PER_SOCKET_CONTEXT *pairedConnection;
	LoadBalance::Backend *selectedBackend;
	LoadBalance::BackendPool *selectedPool;

	// Constructor, allow uninitialized socket and set closing to false (client connection active)
	PER_SOCKET_CONTEXT(SOCKET s = INVALID_SOCKET) : socket(s), closing(false), pendingIO(0), tlsEnabled(false), isBackendConnection(false), pairedConnection(nullptr), selectedBackend(nullptr), selectedPool(nullptr) {}

	// create the Connection object
	void enableTLS(SSL_CTX *ctx)
	{
		tlsConn = std::make_unique<TLS::Connection>(ctx, true);
		tlsEnabled = true;
	}
};

// Forward declarations for TLS functions
void sendTLSPendingData(PER_SOCKET_CONTEXT *sockCtx);
void sendTLSData(PER_SOCKET_CONTEXT *sockCtx, const char *plainData, size_t len);
void handleTLSRead(PER_SOCKET_CONTEXT *sockCtx, const char *data, DWORD bytesReceived);
void processPlainData(PER_SOCKET_CONTEXT *sockCtx, const char *data, DWORD len, HANDLE iocp);

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
	SOCKET upstreamSocket;  // for opType == CONNECT_UPSTREAM, READ_UPSTREAM, WRITE_UPSTREAM
	PER_SOCKET_CONTEXT *upstreamCtx;  // context for upstream socket operations
	// Constructor
	PER_IO_OPERATION_DATA(OpType t = OpType::READ) : buffer(nullptr), opType(t), flags(0), acceptSocket(INVALID_SOCKET), upstreamSocket(INVALID_SOCKET), upstreamCtx(nullptr)
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

		if(upstreamSocket != INVALID_SOCKET){
			closesocket(upstreamSocket);
			upstreamSocket = INVALID_SOCKET;
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

PER_IO_OPERATION_DATA *post_connect_upstream(PER_SOCKET_CONTEXT *upstreamCtx, const std::string& host, unsigned short port, HANDLE iocp){
	auto *ioData = new PER_IO_OPERATION_DATA(OpType::CONNECT_UPSTREAM);
	ioData->upstreamSocket = upstreamCtx->socket;
	ioData->upstreamCtx = upstreamCtx;

	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	int rc = inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
	if(rc != 1){
		std::cerr << "Failed to parse backend host: " << host << std::endl;
		delete ioData;
		return nullptr;
	}

	LPFN_CONNECTEX lpfnConnectEx = nullprt;
	GUID guidConnectEx = WSAIT_CONNECTEX;
	DWORD bytes = 0;

	rc = WSAIoctl(
		upstreamCtx->socket,
		SIO_GET_EXTENSION_FUNCTION_POINTER,
		&guidConnectEx,
		sizeof(guidConnectEx),
		&lpfnConnectEx,
		sizeof(lpfnConnectEx),
		&bytes,
		nullptr,
		nullptr
	);

	if(rc == SOCKET_ERROR || !lpfnConnectEx){
		std::cerr << "Failed to get ConnectEx function pointer" << std::endl;
		delete ioData;
		return nullptr;
	}

	upstreamCtx->pendingIO.fetch_add(1, std::memory_order_relaxed);

	BOOL ok = lpfnConnectEx(
		upstreamCtx->socket,
		(sockaddr*)&addr,
		sizeof(addr),
		nullptr,
		0,
		nullptr,
		&ioData->overlapped
	);

	if(!ok){
		int err = WSAGetLastError();
		if(err != WSA_IO_PENDING){
			upstreamCtx->pendingIO.fetch_sub(1, std::memory_order_relaxed);
			std::cerr << "ConnectEx failed: " << err << std::endl;
			delete ioData;
			return nullptr;
		}
	}

	std::cout << "ConnectEx posted to backend: " << host << ":" << port << std::endl;
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
		if (ctx->tlsEnabled && ctx->tlsConn)
		{
			ctx->tlsConn->shutdown();
			if (ctx->tlsConn->hasNetworkDataPending())
			{
				char buf[BUF_SIZE];
				size_t len = ctx->tlsConn->getNetworkData(buf, sizeof(buf));
				if (len > 0)
				{
					// blocking send. fine for closing.
					send(ctx->socket, buf, (int)len, 0);
				}
			}
		}
		shutdown(ctx->socket, SD_BOTH);
		closesocket(ctx->socket);
		ctx->socket = INVALID_SOCKET;
	}
	delete ctx;
}

void initializeLoadBalancer()
{
	auto &apiPool = g_loadBalancer.createPool("api-servers");
	apiPool.addBackend("127.0.0.1", 3001);
	apiPool.addBackend("127.0.0.1", 3002);
	apiPool.addBackend("127.0.0.1", 3003);

	auto &staticPool = g_loadBalancer.createPool("static-servers");
	staticPool.addBackend("127.0.0.1", 4001);
	staticPool.addBackend("127.0.0.1", 4002);

	g_loadBalancer.addRoute(LoadBalance::Route("/api/", "*", "api-servers", 10));
	g_loadBalancer.addRoute(LoadBalance::Route("/static/", "*", "static-servers", 10));

	g_loadBalancer.setDefaultPool("api-servers");
}

void processPlainData(PER_SOCKET_CONTEXT *sockCtx, const char *data, DWORD len, HANDLE iocp)
{
	std::cout << "Received " << len << " bytes of application data\n"
			  << std::endl;
	if (!g_rateLimiter.allowRequest(sockCtx->clientIP))
	{
		std::string response = RateLimit::build429Response(
			g_rateLimiter.getRetryAfter(sockCtx->clientIP),
			g_rateLimiter.getConfig().maxTokens,
			g_rateLimiter.getRemainingTokens(sockCtx->clientIP));
		sendTLSData(sockCtx, response.c_str(), response.size());
		return;
	}

	sockCtx->httpParser.feed(data, len);

	std::cout << "http parser feed completed" << std::endl;

	if (sockCtx->httpParser.hasError())
	{
		std::cerr << "HTTP parse error: " << sockCtx->httpParser.getError() << std::endl;
		std::string response = HTTP::buildErrorResponse(400, sockCtx->httpParser.getError());
		sendTLSData(sockCtx, response.c_str(), response.size());

		if (!sockCtx->closing.exchange(true))
		{
			CancelIoEx((HANDLE)sockCtx->socket, NULL);
		}
		return;
	}

	std::cout << "no error in http parser" << std::endl;

	if (!sockCtx->httpParser.isComplete())
	{
		return;
	}

	std::cout << "parsing data complete" << std::endl;

	const HTTP::Request &request = sockCtx->httpParser.getRequest();

	std::cout << "HTTP Request " << std::endl;
	std::cout << "Method: " << request.methodStr << std::endl;
	std::cout << "Path: " << request.path << std::endl;
	std::cout << "Host: " << request.getHost() << std::endl;
	std::cout << "Keep-Alive: " << (request.isKeepAlive() ? "yes" : "no") << std::endl;

	LoadBalance::Backend *backend = g_loadBalancer.selectBackendForRequest(
		request.getHost(),
		request.path,
		sockCtx->clientIP);

	if (!backend)
	{
		std::cerr << "No healthy backend available" << std::endl;
		std::string response = HTTP::buildErrorResponse(503, "No backend servers available");
		sendTLSData(sockCtx, response.c_str(), response.size());
		sockCtx->httpParser.reset();
		return;
	}

	std::cout << "Selected Backend: " << backend->getAddress() << std::endl;

	std::string forwardedRequest = HTTP::buildForwardedRequest(
		request,
		sockCtx->clientIP,
		sockCtx->tlsEnabled
	);

	std::cout << "Forwarded Request to backend" << std::endl;
	std::cout << forwardedRequest << std::endl;

	PER_SOCKET_CONTEXT *upstreamCtx = new PER_SOCKET_CONTEXT();
	upstreamCtx->clientIP = "upstream-" + backend->getAddress();
	upstreamCtx->isBackendConnection = true;

	sockCtx->pairedConnection = upstreamCtx;
	upstreamCtx->pairedConnection = sockCtx;

	auto upstreamConn = std::make_unique<Upstream::Connection>(backend->host, backend->port);

	if(!upstreamConn->initiateAsyncConnect(iocp)){
		std::cerr << "Failed to initiate upstream connection" << std::endl;
		std::string response = HTTP::buildErrorResponse(503, "Failed to connect to backend");
		sendTLSData(sockCtx, response.c_str(), response.size());

		upstreamCtx->pairedConnection = nullptr;
		sockCtx->pairedConnection = nullptr;
		delete upstreamCtx;
		return;
	}

	upstreamCtx->socket = upstreamConn->getSocket();

	upstreamCtx->appDataBuffer.assign(forwardedRequest.begin(), forwardedRequest.end());

	std::ostringstream response;
	response << "HTTP/1.1 200 OK\r\n";
	response << "X-Routed-To: " << backend->getAddress() << "\r\n";
	response << "Content-Type: text/plain\r\n";
	response << "Connection: " << (request.isKeepAlive() ? "keep-alive" : "close") << "\r\n";
	std::string body = "Request routed to backend: " + backend->getAddress() + "\n";
	response << "Content-Length: " << body.size() << "\r\n";
	response << "\r\n";
	response << body;

	std::string responseStr = response.str();
	sendTLSData(sockCtx, responseStr.c_str(), responseStr.size());

	// Reset parser for keep-alive or close connection
	if (request.isKeepAlive())
	{
		sockCtx->httpParser.reset();
	}
	else
	{
		if (!sockCtx->closing.exchange(true))
		{
			CancelIoEx((HANDLE)sockCtx->socket, NULL);
		}
	}
}

// handling raw encrypted data from the network, including the first ClientHello message itself
void handleTLSRead(PER_SOCKET_CONTEXT *sockCtx, const char *data, DWORD bytesReceived)
{
	// Log raw encrypted data (will be garbage)
	std::cout << "\n=== RAW NETWORK DATA (" << bytesReceived << " bytes) ===" << std::endl;
	std::cout << "First 32 bytes (hex): ";
	for (DWORD i = 0; i < std::min(bytesReceived, 32UL); i++)
	{
		printf("%02X ", (unsigned char)data[i]);
	}

	std::cout << std::endl;
	if (!sockCtx->tlsEnabled)
	{
		processPlainData(sockCtx, data, bytesReceived, iocp);
		return;
	}

	auto &tls = sockCtx->tlsConn;

	// feed encrypted data to OpenSSL.
	tls->feedNetworkData(data, bytesReceived);

	// if handshake is not completed, the current read could be the ClientHello or the final client message in the handshake
	if (tls->getState() != TLS::State::ESTABLISHED)
	{
		// execute the next step in the state machine.
		TLS::IOResult result = tls->doHandshake();

		// if it was a ClientHello read, OpenSSL could have some data to write back to the client
		if (tls->hasNetworkDataPending())
		{
			sendTLSPendingData(sockCtx);
		}

		if (result == TLS::IOResult::SUCCESS)
		{
			std::cout << "TLS handshake complete: " << tls->getVersion() << " " << tls->getCipher() << "\n\n";
			if (!tls->getSNI().empty())
			{
				std::cout << "SNI: " << tls->getSNI() << "\n";
			}

			// After Handshake is complete, there might be some data sent by the client along with the finished message.
			// OpenSSL already decrypts the message
			char plainBuffer[BUF_SIZE];
			size_t bytesRead = 0;

			TLS::IOResult readResult = tls->read(plainBuffer, sizeof(plainBuffer), bytesRead);
			if (readResult == TLS::IOResult::SUCCESS && bytesRead > 0)
			{
				processPlainData(sockCtx, plainBuffer, static_cast<DWORD>(bytesRead), iocp);
			}
			// next post_recv is posted by the worker thread after this function returns.
		}
		else if (result == TLS::IOResult::WANT_READ)
		{
			// post_recv(sockCtx); -- recv is posted by worker thread
		}
		else if (result == TLS::IOResult::IO_ERROR)
		{
			std::cerr << "TLS handshake failed" << std::endl;
			if (!sockCtx->closing.exchange(true))
			{
				CancelIoEx((HANDLE)sockCtx->socket, NULL);
			}
		}
		return;
	}

	// if TLS is established, reading the data
	char plainBuffer[BUF_SIZE];
	size_t bytesRead = 0;
	bool shouldClose = false;
	bool hasError = false;

	// keep reading the decrypted data.
	while (true)
	{
		TLS::IOResult result = tls->read(plainBuffer, sizeof(plainBuffer), bytesRead);

		if (result == TLS::IOResult::SUCCESS && bytesRead > 0)
		{
			processPlainData(sockCtx, plainBuffer, static_cast<DWORD>(bytesRead), iocp);
		}
		else if (result == TLS::IOResult::WANT_READ)
		{
			// post_recv(sockCtx);  -- posting recv by worker thread
			break;
		}
		else if (result == TLS::IOResult::CLOSED)
		{
			std::cout << "TLS connection closed by peer " << std::endl;
			shouldClose = true;
			break;
		}
		else
		{
			std::cerr << "TLS read error " << std::endl;
			hasError = true;
			break;
		}
	}

	if (shouldClose || hasError)
	{
		if (!sockCtx->closing.exchange(true))
		{
			CancelIoEx((HANDLE)sockCtx->socket, NULL);
		}
	}
}

// send plain data or encrypted data
void sendTLSData(PER_SOCKET_CONTEXT *sockCtx, const char *plainData, size_t len)
{
	// is tls not enabled, just sending plain data.
	if (!sockCtx->tlsEnabled)
	{
		post_send(sockCtx, plainData, static_cast<DWORD>(len));
		return;
	}

	auto &tls = sockCtx->tlsConn;

	if (tls->getState() != TLS::State::ESTABLISHED)
	{
		std::cerr << "Cannot send data : TLS not established" << std::endl;
		return;
	}
	size_t totalWritten = 0;

	while (totalWritten < len)
	{
		size_t bytesWritten = 0;
		TLS::IOResult result = tls->write(
			plainData + totalWritten,
			len - totalWritten,
			bytesWritten);

		if (result == TLS::IOResult::SUCCESS)
		{
			totalWritten += bytesWritten;
		}
		else if (result == TLS::IOResult::WANT_WRITE)
		{
			sendTLSPendingData(sockCtx);
		}
		else if (result == TLS::IOResult::WANT_READ)
		{
			break;
		}
		else
		{
			std::cerr << "TLS write error" << std::endl;
			break;
		}
	}

	if (tls->hasNetworkDataPending())
	{
		sendTLSPendingData(sockCtx);
	}
}

// send the OpenSSL data from the wbio
void sendTLSPendingData(PER_SOCKET_CONTEXT *sockCtx)
{
	auto &tls = sockCtx->tlsConn;
	char encryptedBuffer[BUF_SIZE];

	// loop to completely send the data put in the OpenSSL buffer.
	while (tls->hasNetworkDataPending())
	{
		size_t bytesToSend = tls->getNetworkData(encryptedBuffer, sizeof(encryptedBuffer));
		if (bytesToSend > 0)
		{
			post_send(sockCtx, encryptedBuffer, static_cast<DWORD>(bytesToSend));
		}
	}
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

	// OpenSSL initialization
	TLS::Context::initLibrary();

	if (!g_tlsContext.initServer("server.crt", "server.key"))
	{
		std::cerr << "Failed to initialize TLS context\n";
		return 1;
	}

	std::cout << "TLS initialized successfully\n";

	initializeLoadBalancer();

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

						std::string clientIP = ProxyUtil::getClientIPFromAcceptEx(
							g_listenSocket,
							ioData->buffer,
							ACCEPT_ADDR_LEN,
							ACCEPT_ADDR_LEN
						);

						// check the rate limit status for the client
						if(!g_rateLimiter.allowRequest(clientIP)){
							// get the 429 HTTP response
							std::string response = RateLimit::build429Response(
								g_rateLimiter.getRetryAfter(clientIP),
								g_rateLimiter.getConfig().maxTokens,
								g_rateLimiter.getRemainingTokens(clientIP)
							);

							// blocking
							closesocket(accepted);
							delete ioData;

							post_accept(iocp);
							continue;
						}

						PER_SOCKET_CONTEXT* sockCtx = new PER_SOCKET_CONTEXT(accepted);
						sockCtx->clientIP = clientIP;
						sockCtx->enableTLS(g_tlsContext.get());

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

				if(ioData->opType == OpType::CONNECT_UPSTREAM){
					PER_SOCKET_CONTEXT* upstreamCtx = ioData->upstreamCtx;
					PER_SOCKET_CONTEXT* clientCtx = upstreamCtx->pairedConnection;

					DWORD err = 0;
					if(!ok){
						err = GetLastError();
						std::cerr << "ConnectEx failed: " << err << std::endl;

						if(clientCtx){
							std::string response = HTTP::buildErrorResponse(503, "Failed to connect to backend");
							sendTLSData(clientCtx, response.c_str(), response.size());
							if(!clientCtx->closing.exchange(true)){
								CancelIoEx((HANDLE)clientCtx->socket, NULL);
							}
						}

						upstreamCtx->pendingIO.fetch_sub(1, std::memory_order_relaxed);
						if(!upstreamCtx->closing.exchange(true)){
							CancelIoEx((HANDLE)upstreamCtx->socket, NULL);
						}
						delete ioData;
						continue;
					}

					std::cout << "Connected to upstream backend" << std::endl;
					upstreamCtx->markConnected();

					if(!upstreamCtx->appDataBuffer.empty()){
						PER_IO_OPERATION_DATA* sendOp = post_send(upstreamCtx,
							upstreamCtx->appDataBuffer.data(),
						    static_cast<DWORD>(upstreamCtx->appDataBuffer.size()));

						if(!sendOp){
							std::cerr << "Failed to post send to upstream" << std::endl;
						}
					}

					upstreamCtx->pendingIO.fetch_sub(1, std::memory_order_relaxed);
					delete ioData;

					PER_IO_OPERATION_DATA* recvOp = new PER_IO_OPERATION_DATA(OpType::READ_UPSTREAM);
					recvOp->buffer = new char[BUF_SIZE];
					recvOp->wsaBuf.buf = recvOp->buffer;
					recvOp->wsaBuf.len = BUF_SIZE;
					recvOp->upstreamCtx = upstreamCtx;
					recvOp->upstreamSocket = upstreamCtx->socket;
					ZeroMemory(&recvOp->overlapped, sizeof(recvOp->overlapped));

					upstreamCtx->pendingIO.fetch_add(1, std::memory_order_relaxed);

					DWORD bytesReceived = 0;
					int rc = WSARecv(
						upstreamCtx->socket,
						&recvOp->wsaBuf,
						1,
						&bytesReceived,
						&recvOp->flags,
						&recvOp->overlapped,
						nullptr
					);

					if(rc == SOCKET_ERROR){
						int recvErr = WSAGetLastError();
						if(recvErr != WSA_IO_PENDING){
							std::cerr << "WSARecv on upstream failed: " << recvErr << std::endl;
							upstreamCtx->pendingIO.fetch_sub(1, std::memory_order_relaxed);
							delete recvOp;
						}
					}
					continue;
				}


				// if bytesTransferred 0 and operation is read, it means the client closed connection on sending end.
				// Here, we close the socket operations, deallocate memory
				if (bytesTransferred == 0 && ioData->opType == OpType::READ) {
					std::cout << "Client disconnected" << std::endl;

					if(sockCtx->tlsEnabled && sockCtx->tlsConn){
						sockCtx->tlsConn->shutdown();
						// sending close notify
						if(sockCtx->tlsConn->hasNetworkDataPending()){
							sendTLSPendingData(sockCtx);
						}
					}

					if(!sockCtx->closing.exchange(true)){
						CancelIoEx((HANDLE)sockCtx->socket, NULL);
					}
					int remain = sockCtx->pendingIO.fetch_sub(1) - 1;
					if(remain == 0){
						safeClose(sockCtx);
					}
					delete ioData;
					continue;
				}

				if (ioData->opType == OpType::READ) {
					std::cout << "Read " << bytesTransferred << " bytes from client" << std::endl;

					// Process through TLS first (handshake or decrypt)
					handleTLSRead(sockCtx, ioData->buffer, bytesTransferred);

					
					int remain = sockCtx->pendingIO.fetch_sub(1) - 1;  //fetch sub return previous value
					if(remain == 0 && sockCtx->closing.load()){
						safeClose(sockCtx);
					}

					if(!sockCtx->closing.load()){
						PER_IO_OPERATION_DATA* nextRecv = post_recv(sockCtx);
						if (!nextRecv) {
							std::cerr << "Failed to post receive, closing client." << std::endl;
							if(!sockCtx->closing.exchange(true)){
								CancelIoEx((HANDLE)sockCtx->socket, NULL);
							}
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
	TLS::Context::cleanupLibrary();
	WSACleanup();
	std::cout << "Server stopped successfully" << std::endl;
	return 0;
}