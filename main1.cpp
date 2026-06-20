#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>   // for acceptex, connectex
#include <iostream>
#include <string>
#include <vector>
#include <atomic>
#include <memory>
#include <cassert>
#include <algorithm>
#include <thread>
#include <sstream>
#include <mutex>
#include "proxy.h"
#include "tls/tls_context.h"
#include "tls/tls_connection.h"
#include "http_parser.h"
#include "load_balancer.h"
#include "upstream.h"

constexpr unsigned short LISTEN_PORT = 8080;
constexpr int WORKER_THREADS = 0;
constexpr int BUF_SIZE = 16 * 1024;
constexpr int BACKLOG = 128;
constexpr int ACCEPT_ADDR_LEN = sizeof(sockaddr_in) + 16;


RateLimit::Limiter g_rateLimiter(RateLimit::Config(100.0, 10.0, true));

TLS::Context g_tlsContext;

LoadBalance::LoadBalancer g_loadBalancer;

HANDLE g_iocp = nullptr;

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

enum class OpType : uint32_t{
    READ = 1,
    WRITE = 2,
    ACCEPT = 3,
    CONNECT_UPSTREAM = 4,
    READ_UPSTREAM = 5,
    WRITE_UPSTREAM = 6
};

struct PER_SOCKET_CONTEXT{
    SOCKET socket;

    std::atomic<bool> closing;
    std::atomic<int> pendingIO;
    std::string clientIP;
    std::unique_ptr<TLS::Connection> tlsConn;
    bool tlsEnabled;
    std::vector<char> tlsInputBuffer;
    std::vector<char> tlsOutputBuffer;
    std::vector<char> clientToUpstreamBuffer;
    std::mutex clientToUpstreamMutex;
    std::atomic<bool> upstreamBusy{false};
    std::vector<char> upstreamToClientBuffer;
    std::mutex upstreamToClientMutex;
    std::atomic<bool> clientSendBusy{false};

    HTTP::Parser httpParser;
    bool isBackendConnection;
    PER_SOCKET_CONTEXT *pairedConnection;
    LoadBalance::Backend *selectedBackend;
    LoadBalance::BackendPool *selectedPool;

    PER_SOCKET_CONTEXT(SOCKET s = INVALID_SOCKET) : 
        socket(s),
        closing(false),
        pendingIO(0),
        tlsEnabled(false),
        isBackendConnection(false),
        pairedConnection(nullptr),
        selectedBackend(nullptr),
        selectedPool(nullptr)
    {}

    void enableTLS(SSL_CTX *ctx){
        tlsConn = std::make_unique<TLS::Connection>(ctx, /*server=*/true);
        tlsEnabled = true;
    }
};


struct PER_IO_OPERATION_DATA{
    OVERLAPPED overlapped;
    WSABUF wsaBuf;
    char *buffer;
    OpType opType;
    DWORD flags;
    SOCKET acceptSocket;
    SOCKET upstreamSocket;
    PER_SOCKET_CONTEXT *upstreamCtx;

    PER_IO_OPERATION_DATA(OpType t = OpType::READ):
        buffer(nullptr),
        opType(t),
        flags(0),
        acceptSocket(INVALID_SOCKET),
        upstreamSocket(INVALID_SOCKET),
        upstreamCtx(nullptr){
            ZeroMemory(&overlapped, sizeof(overlapped));
            wsaBuf.buf = nullptr;
            wsaBuf.len = 0;
        }
    
    ~PER_IO_OPERATION_DATA(){
        if(buffer){
            delete[] buffer;
            buffer = nullptr;
        }
        if(acceptSocket != INVALID_SOCKET){
            closesocket(acceptSocket);
            acceptSocket = INVALID_SOCKET;
        }
        if(upstreamSocket != INVALID_SOCKET){
            closesocket(upstreamSocket);
            upstreamSocket = INVALID_SOCKET;
        }
    }
};

void sendTLSPendingData(PER_SOCKET_CONTEXT *sockCtx);
void sendTLSData(PER_SOCKET_CONTEXT *sockCtx, const char *plainData, size_t len);
void handleTLSRead(PER_SOCKET_CONTEXT *sockCtx, const char *data, DWORD bytesReceived);
void processPlainData(PER_SOCKET_CONTEXT *sockCtx, const char *data, DWORD len, HANDLE iocp);

PER_IO_OPERATION_DATA *post_recv(PER_SOCKET_CONTEXT *sockCtx);

// could merge these send functions into one maybe..
PER_IO_OPERATION_DATA *post_send(PER_SOCKET_CONTEXT *sockCtx, const char *data, DWORD len);
PER_IO_OPERATION_DATA *post_send_upstream(PER_SOCKET_CONTEXT *upstreamCtx, const char *data, DWORD len);

PER_IO_OPERATION_DATA *post_accept(HANDLE iocp);

void safeClose(PER_SOCKET_CONTEXT *ctx);

void print_wsa_error(const char *msg){
    int err = WSAGetLastError();
    std::cerr << msg << " WSAGetLastError= " << err << "\n";
}

PER_IO_OPERATION_DATA *post_recv(PER_SOCKET_CONTEXT *sockCtx){
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
        &ioData->overlapped,
        nullptr
    );

    if(rc == SOCKET_ERROR){
        int err = WSAGetLastError();
        if(err != WSA_IO_PENDING){
            sockCtx->pendingIO.fetch_sub(1, std::memory_order_relaxed);
            print_wsa_error("WSARecv failed");
            delete ioData;
            return nullptr;
        }
    }
    return ioData;
}

PER_IO_OPERATION_DATA *post_send(PER_SOCKET_CONTEXT *sockCtx, const char *data, DWORD len){
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
        &ioData->overlapped,
        nullptr
    );

    if(rc == SOCKET_ERROR){
        int err = WSAGetLastError();
        if(err != WSA_IO_PENDING){
            sockCtx->pendingIO.fetch_sub(1, std::memory_order_relaxed);
            print_wsa_error("WSASend failed");
            delete ioData;
            return nullptr;
        }
    }
    return ioData;
}

PER_IO_OPERATION_DATA *post_send_upstream(PER_SOCKET_CONTEXT *upstreamCtx, const char *data, DWORD len){
    auto *ioData = new PER_IO_OPERATION_DATA(OpType::WRITE_UPSTREAM);
    ioData->buffer = new char[len];
    memcpy(ioData->buffer, data, len);
    ioData->wsaBuf.buf = ioData->buffer;
    ioData->wsaBuf.len = len;
    ioData->upstreamSocket = upstreamCtx->socket;
    ioData->upstreamCtx = upstreamCtx;
    ZeroMemory(&ioData->overlapped, sizeof(ioData->overlapped));

    upstreamCtx->pendingIO.fetch_add(1, std::memory_order_relaxed);

    DWORD bytesSent = 0;
    int rc = WSASend(
        upstreamCtx->socket,
        &ioData->wsaBuf,
        1,
        &bytesSent,
        0,
        &ioData->overlapped,
        nullptr
    );

    if(rc == SOCKET_ERROR){
        int err = WSAGetLastError();
        if(err != WSA_IO_PENDING){
            upstreamCtx->pendingIO.fetch_sub(1, std::memory_order_relaxed);
            std::cerr << "WSASend to upstream failed: " << err << "\n";
            delete ioData;
            return nullptr;
        }
    }
    return ioData;
}


PER_IO_OPERATION_DATA *post_accept(HANDLE iocp){
    if(!g_AcceptEx) return nullptr;

    auto *ioData = new PER_IO_OPERATION_DATA(OpType::ACCEPT);

    ioData->buffer = new char[ACCEPT_ADDR_LEN * 2];
    ioData->wsaBuf.buf = ioData->buffer;
    ioData->wsaBuf.len = ACCEPT_ADDR_LEN * 2;

    SOCKET acceptSock = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0. WSA_FLAG_OVERLAPPED);

    if(acceptSock == INVALID_SOCKET){
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
        &ioData->overlapped
    );

    if(!ok){
        int err = WSAGetLastError();
        if(err != ERROR_IO_PENDING && err != WSA_IO_PENDING){
            print_wsa_error("AcceptEx failed");
            closesocket(acceptSock);
            delete ioData;
            return nullptr;
        }
    }
    return ioData;
}

bool init_acceptex(SOCKET listenSock){
    g_listenSocket = listenSock;

    GUID guidAcceptEx = WSAID_ACCEPTEX;
    DWORD bytes = 0;
    int rc = WSAIoctl(
        listenSock,
        SIO_GET_EXTENSION_FUNCTION_POINTER,
        &guidAcceptEx, 
        sizeof(guidAcceptEx),
        &g_AcceptEx, 
        sizeof(g_AcceptEx),
        &bytes,
        nullptr, 
        nullptr
    );

    if(rc == SOCKET_ERROR){
        print_wsa_error("WSAIoctl failed: could not get AcceptEx pointer");
        return false;
    }
    return true;
}

void safeClose(PER_SOCKET_CONTEXT *ctx){
    if(ctx->socket != INVALID_SOCKET){
        if(ctx->socket != INVALID_SOCKET){
            if(ctx->tlsEnabled && ctx->tlsConn){
                ctx->tlsConn->shutdown();

                if(ctx->tlsConn->hasNetworkDataPending()){
                    char buf[BUF_SIZE];
                    size_t len = ctx->tlsConn->getNetworkData(buf, sizeof(buf));
                    if(len > 0){
                        int bytesSent = send(ctx->socket, buf, (int)len, 0);
                        if(bytesSent == SOCKET_ERROR){
                            print_wsa_error("send() failed during TLS shutdown");
                        }
                    }
                }
            }
        }
        shutdown(ctx->socket, SD_BOTH);
        closesocket(ctx->socket);
        ctx->socket = INVALID_SOCKET;
    }
    delete ctx;
}


void initializeLoadBalance(){
    auto &apiPool = g_loadBalancer.createPool("api-servers");
    apiPool.addBackend("127.0.0.1", 3001);
    apiPool.addBackend("127.0.0.1", 3002);
    apiPool.addBackend("127.0.0.1", 3003);

    auto &staticPool = g_loadBalancer.createPool("static-servers");
    staticPool.addBackend("127.0.0.1", 4001);
    staticPool.addBackend("127.0.0.1", 4002);

    g_loadBalancer.addRoute(LoadBalance::Route("/api/", "*", "api-servers", 10));
    g_loadBalancer.addRoute(LoadBalance::Route("/static", "*", "static-servers", 10));

    g_loadBalancer.setDefaultPool("api-servers");
}


void processPlainData(PER_SOCKET_CONTEXT *sockCtx, const char *data, DWORD len, HANDLE iocp){
    std::cout << "Received " << len << " bytes of plain application data\n";

    if(!g_rateLimiter.allowRequest(sockCtx->clientIP)){
       
        std::string response = RateLimit::build429Response(
            g_rateLimiter.getRetryAfter(sockCtx->clientIP),
            g_rateLimiter.getConfig().maxTokens,
            g_rateLimiter.getRemainingTokens(sockCtx->clientIP));
        
        sendTLSData(sockCtx, response.c_str(), response.size());
        return;
    }

    sockCtx->httpParser.feed(data, len);

    if(sockCtx->httpParser.hasError()){
        std::cerr << "HTTP parse error: " << sockCtx->httpParser.getError() << "\n";
        std::string response = HTTP::buildErrorResponse(400, sockCtx->httpParser.getError());
        sendTLSData(sockCtx, response.c_str(), response.size());

        if(!sockCtx->closing.exchange(true)){
            CancelIoEx((HANDLE)sockCtx->socket, NULL);
        }
        return;
    }

    if(!sockCtx->httpParser.isComplete()) return;

    const HTTP::Request &request = sockCtx->httpParser.getRequest();

    std::cout << "HTTP " << request.methodStr << " " << request.path << "Host = " << request.getHost() << " Keep-alive = " << (request.isKeepAlive() ? "yes" : "no") << "\n";

    LoadBalance::Backend *backend = g_loadBalancer.selectBackendForRequest(
        request.getHost(),
        request.path,
        sockCtx->clientIP
    );

    if(!backend){
        std::cerr << "No health backend available \n";
        std::string response = HTTP::buildErrorResponse(503, "No backend servers available");
        sendTLSData(sockCtx, response.c_str(), response.size());
        sockCtx->httpParser.reset();
        return;
    }

    std::cout << "Selected backend: " << backend->getAddress() << "\n";

    std::string forwardedRequest = HTTP::buildForwardedRequest(
        request,
        sockCtx->clientIP,
        sockCtx->tlsEnabled
    );

    std::unique_lock<std::mutex> lock(sockCtx->clientToUpstreamMutex);
    sockCtx->clientToUpstreamBuffer.insert(sockCtx->clientToUpstreamBuffer.end(),
        forwardedRequest.begin(), forwardedRequest.end()
    );

    if(sockCtx->pairedConnection) return;


    PER_SOCKET_CONTEXT *upstreamCtx = new PER_SOCKET_CONTEXT();
    upstreamCtx->clientIP = "upstream-" + backend->getAddress();
    upstreamCtx->isBackendConnection = true;

    sockCtx->pairedConnection = upstreamCtx;
    upstreamCtx->pairedConnection = sockCtx;

    auto upstreamConn = std::make_unique<Upstream::Connection>(backend->host, backend->port);
    if(!upstreamConn->initiateAsyncConnect(iocp)){
        std::cerr << "Failed to initiate upstream connection\n";
        std::string response = HTTP::buildErrorResponse(503, "Failed to connect to backend");
        sendTLSData(sockCtx, response.c_str(), response.size());

        sockCtx->pairedConnection = nullptr;
        upstreamCtx->pairedConnection = nullptr;
        delete upstreamCtx;
        return;
    }

    upstreamCtx->socket = upstreamConn->getSocket();

    sockaddr_in backendAddr{};
    backendAddr.sin_family = AF_INET;
    backendAddr.sin_port   = htons(backend->port);
    if (inet_pton(AF_INET, backend->host.c_str(), &backendAddr.sin_addr) != 1)
    {
        std::cerr << "Failed to parse backend host: " << backend->host << "\n";
        std::string response = HTTP::buildErrorResponse(503, "Backend host invalid");
        sendTLSData(sockCtx, response.c_str(), response.size());
        sockCtx->pairedConnection    = nullptr;
        upstreamCtx->pairedConnection = nullptr;
        delete upstreamCtx;
        return;
    }
 
    LPFN_CONNECTEX lpfnConnectEx = nullptr;
    GUID guidConnectEx = WSAID_CONNECTEX;
    DWORD bytes = 0;
    int rc = WSAIoctl(
        upstreamCtx->socket,
        SIO_GET_EXTENSION_FUNCTION_POINTER,
        &guidConnectEx,    sizeof(guidConnectEx),
        &lpfnConnectEx,    sizeof(lpfnConnectEx),
        &bytes, nullptr, nullptr);
 
    if (rc == SOCKET_ERROR || !lpfnConnectEx)
    {
        std::cerr << "Failed to get ConnectEx function pointer\n";
        std::string response = HTTP::buildErrorResponse(503, "Internal error");
        sendTLSData(sockCtx, response.c_str(), response.size());
        sockCtx->pairedConnection    = nullptr;
        upstreamCtx->pairedConnection = nullptr;
        delete upstreamCtx;
        return;
    }
 
    PER_IO_OPERATION_DATA *connectOp = new PER_IO_OPERATION_DATA(OpType::CONNECT_UPSTREAM);
    connectOp->upstreamSocket = upstreamCtx->socket;
    connectOp->upstreamCtx    = upstreamCtx;
 
    upstreamCtx->pendingIO.fetch_add(1, std::memory_order_relaxed);
 
    BOOL ok = lpfnConnectEx(
        upstreamCtx->socket,
        (sockaddr *)&backendAddr,
        sizeof(backendAddr),
        nullptr,  
        0,
        nullptr,
        &connectOp->overlapped);
 
    if (!ok)
    {
        int connectErr = WSAGetLastError();
        if (connectErr != WSA_IO_PENDING)
        {
            std::cerr << "ConnectEx failed: " << connectErr << "\n";
            std::string response = HTTP::buildErrorResponse(503, "Failed to connect to backend");
            sendTLSData(sockCtx, response.c_str(), response.size());
            upstreamCtx->pendingIO.fetch_sub(1, std::memory_order_relaxed);
            sockCtx->pairedConnection    = nullptr;
            upstreamCtx->pairedConnection = nullptr;
            delete upstreamCtx;
            delete connectOp;
            return;
        }
    }
 
    std::cout << "ConnectEx posted to backend: " << backend->getAddress() << "\n";
}


void handleTLSRead(PER_SOCKET_CONTEXT *sockCtx, const char *data, DWORD bytesReceived)
{
    
    std::cout << "\n=== RAW NETWORK DATA (" << bytesReceived << " bytes) ===\n"
              << "First 32 bytes (hex): ";
    for (DWORD i = 0; i < std::min(bytesReceived, 32UL); i++)
        printf("%02X ", (unsigned char)data[i]);
    std::cout << "\n";
 
    if (!sockCtx->tlsEnabled)
    {
        processPlainData(sockCtx, data, bytesReceived, g_iocp);
        return;
    }
 
    auto &tls = sockCtx->tlsConn;
 
  
    tls->feedNetworkData(data, bytesReceived);
 
    
    if (tls->getState() != TLS::State::ESTABLISHED)
    {
        TLS::IOResult result = tls->doHandshake();
 
        if (tls->hasNetworkDataPending())
            sendTLSPendingData(sockCtx);
 
        if (result == TLS::IOResult::SUCCESS)
        {
            std::cout << "TLS handshake complete: " << tls->getVersion() << " " << tls->getCipher() << "\n";
            if (!tls->getSNI().empty())
                std::cout << "SNI: " << tls->getSNI() << "\n";
            
            char plainBuffer[BUF_SIZE];
            size_t bytesRead = 0;
            TLS::IOResult readResult = tls->read(plainBuffer, sizeof(plainBuffer), bytesRead);
            if (readResult == TLS::IOResult::SUCCESS && bytesRead > 0) processPlainData(sockCtx, plainBuffer, (DWORD)bytesRead, g_iocp);
        }
        else if (result == TLS::IOResult::WANT_READ)
        {
            
        }
        else if (result == TLS::IOResult::IO_ERROR)
        {
            std::cerr << "TLS handshake failed\n";
            if (!sockCtx->closing.exchange(true))  CancelIoEx((HANDLE)sockCtx->socket, NULL);
        }
        return;
    }
 
    char plainBuffer[BUF_SIZE];
    size_t bytesRead  = 0;
    bool shouldClose = false;
    bool hasError = false;
 
    while (true)
    {
        TLS::IOResult result = tls->read(plainBuffer, sizeof(plainBuffer), bytesRead);
 
        if (result == TLS::IOResult::SUCCESS && bytesRead > 0)
        {
            processPlainData(sockCtx, plainBuffer, (DWORD)bytesRead, g_iocp);
        }
        else if (result == TLS::IOResult::WANT_READ)
        {
           break;
        }
        else if (result == TLS::IOResult::CLOSED)
        {
            std::cout << "TLS close_notify received from peer\n";
            shouldClose = true;
            break;
        }
        else
        {
            std::cerr << "TLS read error\n";
            hasError = true;
            break;
        }
    }
 
    if (shouldClose || hasError)
    {
        if (!sockCtx->closing.exchange(true))
            CancelIoEx((HANDLE)sockCtx->socket, NULL);
    }
}
 
void sendTLSData(PER_SOCKET_CONTEXT *sockCtx, const char *plainData, size_t len)
{
    if (!sockCtx->tlsEnabled)
    {
        post_send(sockCtx, plainData, (DWORD)len);
        return;
    }
 
    auto &tls = sockCtx->tlsConn;
    if (tls->getState() != TLS::State::ESTABLISHED)
    {
        std::cerr << "Cannot send: TLS not established\n";
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
            std::cerr << "TLS write error\n";
            break;
        }
    }
 
    if (tls->hasNetworkDataPending())
        sendTLSPendingData(sockCtx);
}
 
void sendTLSPendingData(PER_SOCKET_CONTEXT *sockCtx)
{
    auto &tls = sockCtx->tlsConn;
    char encryptedBuffer[BUF_SIZE];
 
    while (tls->hasNetworkDataPending())
    {
        size_t bytesToSend = tls->getNetworkData(encryptedBuffer, sizeof(encryptedBuffer));
        if (bytesToSend > 0)
            post_send(sockCtx, encryptedBuffer, (DWORD)bytesToSend);
    }
}
 
int main(int argc, char *argv[])
{
    WSADATA wsaData;
    int wsaerr = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaerr != 0)
    {
        std::cerr << "WSAStartup failed: " << wsaerr << "\n";
        return 1;
    }
    std::cout << "Winsock initialized. Status: " << wsaData.szSystemStatus << "\n";
 
    
    TLS::Context::initLibrary();
    if (!g_tlsContext.initServer("server.crt", "server.key"))
    {
        std::cerr << "Failed to initialize TLS context\n";
        WSACleanup();
        return 1;
    }
    std::cout << "TLS context initialized successfully\n";
 
    
    initializeLoadBalancer();
 
   
    SOCKET listenSocket = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP,
                                     nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (listenSocket == INVALID_SOCKET)
    {
        print_wsa_error("WSASocket (listen) failed");
        WSACleanup();
        return 1;
    }
 
    BOOL reuse = TRUE;
    setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));
 
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;  
    addr.sin_port        = htons(LISTEN_PORT);
 
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
    std::cout << "Listening on port " << LISTEN_PORT << "\n";
 
    HANDLE iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);
    if (!iocp)
    {
        print_wsa_error("CreateIoCompletionPort failed");
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }
    g_iocp = iocp;
 
   
    CreateIoCompletionPort((HANDLE)listenSocket, iocp, 0, 0);
 
    if (!init_acceptex(listenSocket))
    {
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }

    unsigned int cpuCount  = std::max(1u, (unsigned int)std::thread::hardware_concurrency());
    unsigned int numWorkers = (WORKER_THREADS > 0) ? WORKER_THREADS : cpuCount * 2;
    std::atomic<bool> running{true};
    std::vector<std::thread> workers;
    workers.reserve(numWorkers);
 
    std::cout << "Starting " << numWorkers << " worker threads\n";
 
    for (unsigned int i = 0; i < numWorkers; i++)
    {
        workers.emplace_back([iocp, &running]()
        {
            while (running.load())
            {
                DWORD          bytesTransferred = 0;
                ULONG_PTR      completionKey    = 0;
                LPOVERLAPPED   overlapped       = nullptr;
 
                BOOL ok = GetQueuedCompletionStatus(
                    iocp,
                    &bytesTransferred,
                    &completionKey,
                    &overlapped,
                    INFINITE);
 
                PER_SOCKET_CONTEXT    *sockCtx = reinterpret_cast<PER_SOCKET_CONTEXT *>(completionKey);
 
                PER_IO_OPERATION_DATA *ioData  = reinterpret_cast<PER_IO_OPERATION_DATA *>(overlapped);
 
                if (!ioData)
                {
                    if (!running.load()) break;
                    continue;
                }
 
                if (!ok)
                {
                    DWORD err = GetLastError();
 
                    if (overlapped == nullptr)
                    {
                        if (!running.load()) break;
                        std::cerr << "GQCS failed, no overlapped: " << err << "\n";
                        continue;
                    }
 
                    
                    if (ioData->opType == OpType::READ || ioData->opType == OpType::WRITE)
                    {
                        if (sockCtx)
                        {
                            int remain = sockCtx->pendingIO.fetch_sub(1) - 1;
                            if (remain == 0 && sockCtx->closing.load())
                                safeClose(sockCtx);
                        }
                    }
                    std::cerr << "I/O operation failed: " << err << "\n";
                    delete ioData;
                    continue;
                }
 
                if (overlapped == nullptr)
                {
                    if (!running.load()) break;
                    continue;
                }
 
                if (ioData->opType == OpType::ACCEPT)
                {
                    SOCKET accepted = ioData->acceptSocket;
 
                    if (accepted != INVALID_SOCKET)
                    {
                        int rc = setsockopt(accepted, SOL_SOCKET,
                                            SO_UPDATE_ACCEPT_CONTEXT,
                                            (char *)&g_listenSocket, sizeof(g_listenSocket));
                        if (rc == SOCKET_ERROR)
                        {
                            print_wsa_error("SO_UPDATE_ACCEPT_CONTEXT failed");
                            closesocket(accepted);
                            delete ioData;
                            post_accept(iocp); 
                            continue;
                        }
 
                        std::string clientIP = ProxyUtil::getClientIPFromAcceptEx(
                            g_listenSocket,
                            ioData->buffer,
                            ACCEPT_ADDR_LEN,
                            ACCEPT_ADDR_LEN);
 
                       
                        if (!g_rateLimiter.allowRequest(clientIP))
                        {
                            closesocket(accepted);
                            delete ioData;
                            post_accept(iocp);
                            continue;
                        }
 
                        PER_SOCKET_CONTEXT *newClientCtx = new PER_SOCKET_CONTEXT(accepted);
                        newClientCtx->clientIP = clientIP;
 
                        newClientCtx->enableTLS(g_tlsContext.get());
 
                        if (!CreateIoCompletionPort((HANDLE)accepted, iocp,
                                                    (ULONG_PTR)newClientCtx, 0))
                        {
                            print_wsa_error("CreateIoCompletionPort (accepted) failed");
                            closesocket(accepted);
                            delete newClientCtx;
                            delete ioData;
                            post_accept(iocp);
                            continue;
                        }
 
                        PER_IO_OPERATION_DATA *recvOp = post_recv(newClientCtx);
                        if (!recvOp)
                        {
                            std::cerr << "Failed to post initial recv for accepted socket\n";
                            if (!newClientCtx->closing.exchange(true))
                            {
                                closesocket(newClientCtx->socket);
                                delete newClientCtx;
                            }
                        }
 
                        ioData->acceptSocket = INVALID_SOCKET;
                    }
 
                    delete ioData;
 
                    post_accept(iocp);
                    continue;
                }
 
                if (ioData->opType == OpType::CONNECT_UPSTREAM)
                {
                    PER_SOCKET_CONTEXT *upstreamCtx = ioData->upstreamCtx;
                    PER_SOCKET_CONTEXT *clientCtx   = upstreamCtx ? upstreamCtx->pairedConnection : nullptr;
 
                    if (!ok)
                    {
                        DWORD err = GetLastError();
                        std::cerr << "ConnectEx to backend failed: " << err << "\n";
 
                        if (clientCtx)
                        {
                            std::string response = HTTP::buildErrorResponse(503, "Failed to connect to backend");
                            sendTLSData(clientCtx, response.c_str(), response.size());
                            if (!clientCtx->closing.exchange(true))
                                CancelIoEx((HANDLE)clientCtx->socket, NULL);
                        }
                        if (upstreamCtx)
                        {
                            upstreamCtx->pendingIO.fetch_sub(1, std::memory_order_relaxed);
                            if (!upstreamCtx->closing.exchange(true))
                                CancelIoEx((HANDLE)upstreamCtx->socket, NULL);
                        }
                        delete ioData;
                        continue;
                    }
 
                    std::cout << "Connected to upstream backend\n";
 
                    setsockopt(upstreamCtx->socket, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, nullptr, 0);
 
                    if (clientCtx)
                    {
                        std::unique_lock<std::mutex> lock(clientCtx->clientToUpstreamMutex);
 
                        if (!clientCtx->clientToUpstreamBuffer.empty())
                        {
                            PER_IO_OPERATION_DATA *sendOp = post_send_upstream(
                                upstreamCtx,
                                clientCtx->clientToUpstreamBuffer.data(),
                                (DWORD)clientCtx->clientToUpstreamBuffer.size());
 
                            if (sendOp)
                            {
                                clientCtx->upstreamSendBusy.store(true);
                                clientCtx->clientToUpstreamBuffer.clear();
                            }
                        }
                    }
 
                    upstreamCtx->pendingIO.fetch_sub(1, std::memory_order_relaxed);
                    delete ioData;
 
                    PER_IO_OPERATION_DATA *recvOp = new PER_IO_OPERATION_DATA(OpType::READ_UPSTREAM);
                    recvOp->buffer          = new char[BUF_SIZE];
                    recvOp->wsaBuf.buf      = recvOp->buffer;
                    recvOp->wsaBuf.len      = BUF_SIZE;
                    recvOp->upstreamCtx     = upstreamCtx;
                    recvOp->upstreamSocket  = upstreamCtx->socket;
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
                        nullptr);
 
                    if (rc == SOCKET_ERROR)
                    {
                        int recvErr = WSAGetLastError();
                        if (recvErr != WSA_IO_PENDING)
                        {
                            std::cerr << "WSARecv on upstream failed: " << recvErr << "\n";
                            upstreamCtx->pendingIO.fetch_sub(1, std::memory_order_relaxed);
                            delete recvOp;
                        }
                    }
                    continue;
                }
 
                
                if (ioData->opType == OpType::READ)
                {
                    if (bytesTransferred == 0)
                    {
                        std::cout << "Client disconnected (graceful)\n";
 
                        if (sockCtx->tlsEnabled && sockCtx->tlsConn)
                        {
                            sockCtx->tlsConn->shutdown();
                            if (sockCtx->tlsConn->hasNetworkDataPending())
                                sendTLSPendingData(sockCtx);
                        }
 
                        if (!sockCtx->closing.exchange(true))
                            CancelIoEx((HANDLE)sockCtx->socket, NULL);
 
                        int remain = sockCtx->pendingIO.fetch_sub(1) - 1;
                        if (remain == 0)
                            safeClose(sockCtx);
 
                        delete ioData;
                        continue;
                    }
 
                    std::cout << "Read " << bytesTransferred << " bytes from client\n";
 
                    handleTLSRead(sockCtx, ioData->buffer, bytesTransferred);
 
                   
                    int remain = sockCtx->pendingIO.fetch_sub(1) - 1;
                    if (remain == 0 && sockCtx->closing.load())
                    {
                        safeClose(sockCtx);
                        delete ioData;
                        continue;
                    }
 
                    if (!sockCtx->closing.load())
                    {
                        PER_IO_OPERATION_DATA *nextRecv = post_recv(sockCtx);
                        if (!nextRecv)
                        {
                            std::cerr << "Failed to post next recv; closing client\n";
                            if (!sockCtx->closing.exchange(true))
                                CancelIoEx((HANDLE)sockCtx->socket, NULL);
                        }
                    }
 
                    delete ioData;
                    continue;
                }
 
               
                if (ioData->opType == OpType::READ_UPSTREAM)
                {
                    PER_SOCKET_CONTEXT *upstreamCtx = ioData->upstreamCtx;
                    PER_SOCKET_CONTEXT *clientCtx   = upstreamCtx ? upstreamCtx->pairedConnection : nullptr;
 
                    if (bytesTransferred == 0)
                    {
                        std::cout << "Backend disconnected\n";
                        if (clientCtx && !clientCtx->closing.exchange(true))
                            CancelIoEx((HANDLE)clientCtx->socket, NULL);
                        if (upstreamCtx && !upstreamCtx->closing.exchange(true))
                            CancelIoEx((HANDLE)upstreamCtx->socket, NULL);
 
                        if (upstreamCtx)
                            upstreamCtx->pendingIO.fetch_sub(1, std::memory_order_relaxed);
                        delete ioData;
                        continue;
                    }
 
                    std::cout << "Read " << bytesTransferred << " bytes from backend\n";
 
                   
                    if (clientCtx)
                    {
                        std::unique_lock<std::mutex> lock(clientCtx->upstreamToClientMutex);
 
                        clientCtx->upstreamToClientBuffer.insert(
                            clientCtx->upstreamToClientBuffer.end(),
                            ioData->buffer,
                            ioData->buffer + bytesTransferred);
 
                        if (!clientCtx->clientSendBusy.load())
                        {
                            if (clientCtx->tlsEnabled)
                            {
                                sendTLSData(clientCtx,
                                            clientCtx->upstreamToClientBuffer.data(),
                                            clientCtx->upstreamToClientBuffer.size());
                            }
                            else
                            {
                                post_send(clientCtx,
                                          clientCtx->upstreamToClientBuffer.data(),
                                          (DWORD)clientCtx->upstreamToClientBuffer.size());
                            }
                            clientCtx->clientSendBusy.store(true);
                            clientCtx->upstreamToClientBuffer.clear();
                        }
                    }
 
                    upstreamCtx->pendingIO.fetch_sub(1, std::memory_order_relaxed);
 
                    
                    if (!upstreamCtx->closing.load())
                    {
                        PER_IO_OPERATION_DATA *nextRecv = new PER_IO_OPERATION_DATA(OpType::READ_UPSTREAM);
                        nextRecv->buffer         = new char[BUF_SIZE];
                        nextRecv->wsaBuf.buf     = nextRecv->buffer;
                        nextRecv->wsaBuf.len     = BUF_SIZE;
                        nextRecv->upstreamCtx    = upstreamCtx;
                        nextRecv->upstreamSocket = upstreamCtx->socket;
                        ZeroMemory(&nextRecv->overlapped, sizeof(nextRecv->overlapped));
 
                        upstreamCtx->pendingIO.fetch_add(1, std::memory_order_relaxed);
 
                        DWORD bytesReceived = 0;
                        int rc = WSARecv(
                            upstreamCtx->socket,
                            &nextRecv->wsaBuf,
                            1,
                            &bytesReceived,
                            &nextRecv->flags,
                            &nextRecv->overlapped,
                            nullptr);
 
                        if (rc == SOCKET_ERROR)
                        {
                            int recvErr = WSAGetLastError();
                            if (recvErr != WSA_IO_PENDING)
                            {
                                upstreamCtx->pendingIO.fetch_sub(1, std::memory_order_relaxed);
                                delete nextRecv;
                            }
                        }
                    }
 
                    delete ioData;
                    continue;
                }
 
                if (ioData->opType == OpType::WRITE)
                {
                    std::cout << "Write to client complete: " << bytesTransferred << " bytes\n";
 
                    {
                        std::unique_lock<std::mutex> lock(sockCtx->upstreamToClientMutex);
 
                        sockCtx->clientSendBusy.store(false); // inside the lock
 
                        if (!sockCtx->upstreamToClientBuffer.empty())
                        {
                            if (sockCtx->tlsEnabled)
                            {
                                sendTLSData(sockCtx,
                                            sockCtx->upstreamToClientBuffer.data(),
                                            sockCtx->upstreamToClientBuffer.size());
                            }
                            else
                            {
                                post_send(sockCtx,
                                          sockCtx->upstreamToClientBuffer.data(),
                                          (DWORD)sockCtx->upstreamToClientBuffer.size());
                            }
                            sockCtx->clientSendBusy.store(true);
                            sockCtx->upstreamToClientBuffer.clear();
                        }
                    }
 
                    int remain = sockCtx->pendingIO.fetch_sub(1) - 1;
                    if (remain == 0 && sockCtx->closing.load())
                        safeClose(sockCtx);
 
                    delete ioData;
                    continue;
                }
 
                
                if (ioData->opType == OpType::WRITE_UPSTREAM)
                {
                    std::cout << "Write to upstream complete: " << bytesTransferred << " bytes\n";
 
                    PER_SOCKET_CONTEXT *upstreamCtx = ioData->upstreamCtx;
                    PER_SOCKET_CONTEXT *clientCtx   = upstreamCtx ? upstreamCtx->pairedConnection : nullptr;
 
                    if (clientCtx)
                    {
                        std::unique_lock<std::mutex> lock(clientCtx->clientToUpstreamMutex);
 
                        clientCtx->upstreamSendBusy.store(false); 
                        
                        if (!clientCtx->clientToUpstreamBuffer.empty())
                        {
                            PER_IO_OPERATION_DATA *nextSend = post_send_upstream(
                                upstreamCtx,
                                clientCtx->clientToUpstreamBuffer.data(),
                                (DWORD)clientCtx->clientToUpstreamBuffer.size());
 
                            if (nextSend)
                            {
                                clientCtx->upstreamSendBusy.store(true);
                                clientCtx->clientToUpstreamBuffer.clear();
                            }
                        }
                    }
 
                    if (upstreamCtx)
                    {
                        int remain = upstreamCtx->pendingIO.fetch_sub(1) - 1;
                        if (remain == 0 && upstreamCtx->closing.load())
                            safeClose(upstreamCtx);
                    }
 
                    delete ioData;
                    continue;
                }
 
                std::cerr << "Unknown OpType in completion handler\n";
                delete ioData;
 
            } 
        }); 
    }
 
   
    int initial_accepts = std::max(4, (int)numWorkers);
    std::vector<PER_IO_OPERATION_DATA *> pendingAccepts;
    pendingAccepts.reserve(initial_accepts);
    for (int i = 0; i < initial_accepts; i++)
    {
        PER_IO_OPERATION_DATA *acceptData = post_accept(iocp);
        if (acceptData)
            pendingAccepts.push_back(acceptData);
    }
 
   
    std::cout << "Server running. Press Enter to stop...\n";
    std::cin.get();
    std::cout << "Shutting down...\n";
 
    running.store(false);
 
    closesocket(listenSocket);
 
    
    for (size_t i = 0; i < workers.size(); i++)
        PostQueuedCompletionStatus(iocp, 0, 0, nullptr);
 
    for (auto &t : workers)
        if (t.joinable()) t.join();
 
    for (PER_IO_OPERATION_DATA *ioData : pendingAccepts)
        delete ioData;
 
    CloseHandle(iocp);
    TLS::Context::cleanupLibrary();
    WSACleanup();
 
    std::cout << "Server stopped successfully\n";
    return 0;
}