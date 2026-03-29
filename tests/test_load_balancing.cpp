#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include "iostream"
#include <string>
#include <map>
#include <openssl/ssl.h>
#include <openssl/err.h>

class TLSClient
{
private:
    SOCKET sock;
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *rbio; // Read BIO
    BIO *wbio; // Write BIO

public:
    TLSClient() : sock(INVALID_SOCKET), ctx(nullptr), ssl(nullptr), rbio(nullptr), wbio(nullptr) {}

    ~TLSClient()
    {
        disconnect();
        if (ctx)
            SSL_CTX_free(ctx);
    }

    bool init()
    {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();

        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx)
        {
            ERR_print_errors_fp(stderr);
            return false;
        }

        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        return true;
    }

    bool connect(const char *host, int port)
    {
        // creating socket
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET)
        {
            std::cerr << "socket() failed" << std::endl;
            return false;
        }

        sockaddr_in server{};
        server.sin_family = AF_INET;
        server.sin_port = htons(port);
        inet_pton(AF_INET, host, &server.sin_addr);

        if (::connect(sock, (sockaddr *)&server, sizeof(server)) == SOCKET_ERROR)
        {
            std::cerr << "connect() failed: " << WSAGetLastError() << std::endl;
            return false;
        }

        std::cout << "TCP connected to " << host << ":" << port << std::endl;

        ssl = SSL_new(ctx);
        if (!ssl)
        {
            ERR_print_errors_fp(stderr);
            return false;
        }

        rbio = BIO_new(BIO_s_mem());
        wbio = BIO_new(BIO_s_mem());
        BIO_set_nbio(rbio, 1);
        BIO_set_nbio(wbio, 1);
        SSL_set_bio(ssl, rbio, wbio);

        SSL_set_tlsext_host_name(ssl, host);
        SSL_set_connect_state(ssl); // Client mode

        std::cout << "Starting TLS handshake..." << std::endl;

        // handshake
        if (!doHandshake())
        {
            return false;
        }

        std::cout << "=== TLS Connection Established ===" << std::endl;
        std::cout << "Version: " << SSL_get_version(ssl) << std::endl;
        std::cout << "Cipher:  " << SSL_get_cipher_name(ssl) << std::endl;
        std::cout << "==================================" << std::endl;

        return true;
    }

    bool doHandshake()
    {
        char buffer[16384];

        while (true)
        {
            int ret = SSL_do_handshake(ssl);

            // send pending handshake data
            int pending = BIO_ctrl_pending(wbio);
            if (pending > 0)
            {
                int toSend = BIO_read(wbio, buffer, sizeof(buffer));
                if (toSend > 0)
                {
                    ::send(sock, buffer, toSend, 0);
                }
            }

            if (ret == 1)
            {
                // handshake complete
                return true;
            }

            int err = SSL_get_error(ssl, ret);
            if (err == SSL_ERROR_WANT_READ)
            {
                // receive data from server
                int recvLen = ::recv(sock, buffer, sizeof(buffer), 0);
                if (recvLen <= 0)
                {
                    std::cerr << "Handshake recv failed" << std::endl;
                    return false;
                }
                BIO_write(rbio, buffer, recvLen);
            }
            else if (err != SSL_ERROR_WANT_WRITE)
            {
                ERR_print_errors_fp(stderr);
                return false;
            }
        }
    }

    int send(const char *plainData, int len)
    {
        char buffer[16384];

        int written = SSL_write(ssl, plainData, len);
        if (written <= 0)
            return written;

        // getting encrypted data from wbio
        int pending = BIO_ctrl_pending(wbio);
        if (pending > 0)
        {
            int encryptedLen = BIO_read(wbio, buffer, sizeof(buffer));
            return ::send(sock, buffer, encryptedLen, 0);
        }
        return written;
    }

    int recv(char *plainBuffer, int maxLen)
    {
        char buffer[16384];

        // Receive encrypted data from network
        int recvLen = ::recv(sock, buffer, sizeof(buffer), 0);
        if (recvLen <= 0)
            return recvLen;

        // feeding to OpenSSL
        BIO_write(rbio, buffer, recvLen);

        // reading decrypted data
        int decryptedLen = SSL_read(ssl, plainBuffer, maxLen);

        if (decryptedLen > 0)
        {
            return decryptedLen;
        }

        // SSL errors
        int err = SSL_get_error(ssl, decryptedLen);
        if (err == SSL_ERROR_WANT_READ)
        {
            // trying to receive more
            recvLen = ::recv(sock, buffer, sizeof(buffer), 0);
            if (recvLen > 0)
            {
                BIO_write(rbio, buffer, recvLen);
                decryptedLen = SSL_read(ssl, plainBuffer, maxLen);
                if (decryptedLen > 0)
                {
                    return decryptedLen;
                }
            }
        }

        // check if it is a shutdown
        if (err == SSL_ERROR_ZERO_RETURN)
        {
            std::cout << "Server closed TLS connection cleanly" << std::endl;
            return 0;
        }

        ERR_print_errors_fp(stderr);
        return decryptedLen;
    }

    void disconnect()
    {
        if (ssl)
        {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = nullptr;
            rbio = nullptr;
            wbio = nullptr;
        }
        if (sock != INVALID_SOCKET)
        {
            closesocket(sock);
            sock = INVALID_SOCKET;
        }
    }

    bool isConnected() const
    {
        return sock != INVALID_SOCKET && ssl != nullptr;
    }
};

// Helper function to extract backend info from response
std::string extractBackendInfo(const std::string &response)
{
    // Look for header or response that contains backend info
    // Server returns: "X-Routed-To: address:port" or similar
    size_t pos = response.find("X-Routed-To:");
    if (pos != std::string::npos)
    {
        size_t start = pos + 12;
        size_t end = response.find("\r\n", start);
        if (end != std::string::npos)
        {
            return response.substr(start, end - start);
        }
    }

    // Fallback: look for any backend info in body
    pos = response.find("Backend:");
    if (pos != std::string::npos)
    {
        size_t start = pos;
        size_t end = response.find("\n", start);
        if (end != std::string::npos)
        {
            return response.substr(start, end - start);
        }
    }

    return "Unknown";
}

int main(int argc, char *argv[])
{
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        std::cerr << "WSAStartup failed" << std::endl;
        return 1;
    }

    std::cout << "====== LOAD BALANCING VERIFICATION TEST ======" << std::endl;
    std::cout << "Sending multiple requests on single connection" << std::endl;
    std::cout << "===============================================\n"
              << std::endl;

    TLSClient client;
    if (!client.init())
    {
        std::cerr << "Failed to initialize TLS" << std::endl;
        WSACleanup();
        return 1;
    }

    if (!client.connect("127.0.0.1", 8080))
    {
        std::cerr << "Failed to connect to server" << std::endl;
        WSACleanup();
        return 1;
    }

    // Track backend distribution
    std::map<std::string, int> backendCount;
    int totalRequests = 10;

    for (int i = 0; i < totalRequests; i++)
    {
        std::cout << "\n--- Request " << (i + 1) << " ---" << std::endl;

        // Send HTTP request
        std::string httpRequest = "GET /api/users HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n";

        int sent = client.send(httpRequest.c_str(), (int)httpRequest.size());
        if (sent <= 0)
        {
            std::cerr << "Failed to send request" << std::endl;
            break;
        }

        // Receive response
        char recvBuf[4096];
        int recvLen = client.recv(recvBuf, sizeof(recvBuf) - 1);
        if (recvLen > 0)
        {
            recvBuf[recvLen] = '\0';
            std::string response(recvBuf);

            // Extract status line
            size_t statusEnd = response.find("\r\n");
            if (statusEnd != std::string::npos)
            {
                std::cout << "Status: " << response.substr(0, statusEnd) << std::endl;
            }

            // Extract backend info
            std::string backend = extractBackendInfo(response);
            std::cout << "Backend: " << backend << std::endl;

            // Count backend usage
            backendCount[backend]++;

            // Show a snippet of the body
            size_t bodyStart = response.find("\r\n\r\n");
            if (bodyStart != std::string::npos)
            {
                bodyStart += 4;
                size_t bodyEnd = std::min(bodyStart + 100, response.length());
                std::cout << "Response preview: " << response.substr(bodyStart, bodyEnd - bodyStart) << std::endl;
            }
        }
        else if (recvLen == 0)
        {
            std::cout << "Server closed connection" << std::endl;
            break;
        }
        else
        {
            std::cerr << "Failed to receive response" << std::endl;
            break;
        }
    }

    client.disconnect();

    // Print load balancing summary
    std::cout << "\n\n====== LOAD BALANCING SUMMARY ======" << std::endl;
    std::cout << "Total requests sent: " << totalRequests << std::endl;
    std::cout << "\nBackend distribution:" << std::endl;
    for (const auto &pair : backendCount)
    {
        std::cout << "  " << pair.first << ": " << pair.second << " requests" << std::endl;
    }

    if (backendCount.size() > 1)
    {
        std::cout << "\n✓ Load balancing appears to be working (multiple backends used)" << std::endl;
    }
    else if (backendCount.size() == 1)
    {
        std::cout << "\n⚠ All requests went to one backend. Check load balancing algorithm." << std::endl;
    }

    std::cout << "====================================\n"
              << std::endl;

    WSACleanup();
    return 0;
}
