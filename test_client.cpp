#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include "iostream"
#include <string>

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
					printHexDump("CLIENT: SENDING HANDSHAKE (ENCRYPTED)", buffer, toSend);
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
				printHexDump("CLIENT: RECEIVED HANDSHAKE (ENCRYPTED)", buffer, recvLen);
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

		printHexDump("CLIENT: PLAINTEXT TO ENCRYPT", plainData, len);

		int written = SSL_write(ssl, plainData, len);
		if (written <= 0)
			return written;

		// getting encrypted data from wbio
		int pending = BIO_ctrl_pending(wbio);
		if (pending > 0)
		{
			int encryptedLen = BIO_read(wbio, buffer, sizeof(buffer));
			printHexDump("CLIENT: ENCRYPTED BYTES TO SEND", buffer, encryptedLen);
			return ::send(sock, buffer, encryptedLen, 0);
		}
		return written;
	}

	int recv(char *plainBuffer, int maxLen)
	{
		char buffer[16384];

		// Receive encrypted data from network
		int recvLen = ::recv(sock, buffer, sizeof(buffer), 0);
		if(recvLen <= 0)
			return recvLen;


		// feeding to OpenSSL
		BIO_write(rbio, buffer, recvLen);

		// reading decrypted data
		int decryptedLen = SSL_read(ssl, plainBuffer, maxLen);

		if(decryptedLen > 0)
		{
			return decryptedLen;
		}

		// SSL errors
		int err = SSL_get_error(ssl, decryptedLen);
		if(err == SSL_ERROR_WANT_READ)
		{
			// trying to receive more
			recvLen = ::recv(sock, buffer, sizeof(buffer), 0);
			if(recvLen > 0)
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
		if(err == SSL_ERROR_ZERO_RETURN)
		{
			std::cout << "Server closed TLS connection cleanly" << std::endl;
			return 0;
		}

		// print error
		std::cerr << "SSL_read error: " << err << std::endl;
		ERR_print_errors_fp(stderr);
		return decryptedLen;
	}

	void disconnect()
	{
		if(ssl)
		{
			SSL_shutdown(ssl);
			SSL_free(ssl);
			ssl = nullptr;
			rbio = nullptr;
			wbio = nullptr;
		}
		if(sock != INVALID_SOCKET)
		{
			closesocket(sock);
			sock = INVALID_SOCKET;
		}
	}

private:
	void printHexDump(const char *label, const char *data, int len)
	{
		std::cout << "\n========== " << label << " ==========" << std::endl;
		std::cout << "Length: " << len << " bytes" << std::endl;
		std::cout << "Hex: ";
		for(int i = 0; i < std::min(len, 48); i++)
		{
			printf("%02X ", (unsigned char)data[i]);
			if ((i + 1) % 16 == 0 && i + 1 < std::min(len, 48))
				std::cout << "\n     ";
		}
		if(len > 48)
			std::cout << "...";
		std::cout << "\n================================================" << std::endl;
	}
};

int main(int argc, char *argv[])
{
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		std::cerr << "WSAStartup failed" << std::endl;
		return 1;
	}

	TLSClient client;

	if (!client.init())
	{
		std::cerr << "Failed to initialize TLS" << std::endl;
		WSACleanup();
		return 1;
	}

	if (!client.connect("127.0.0.1", 8080))
	{
		std::cerr << "Failed to connect" << std::endl;
		WSACleanup();
		return 1;
	}

	std::cout << "\nConnected! Type messages (or 'exit' to quit)\n" << std::endl;
	char recvBuf[4096];
	while(true)
	{
		std::string msg;
		std::cout << "Enter message: ";
		std::getline(std::cin, msg);

		if(msg == "exit")
			break;

		msg += "\n";
		int sent = client.send(msg.c_str(), (int)msg.size());
		if(sent <= 0)
		{
			std::cerr << "Send Failed" << std::endl;
			break;
		}
		std::cout << "\n>>> Sent successfully" << std::endl;

		int recvLen = client.recv(recvBuf, sizeof(recvBuf) - 1);
		if(recvLen <= 0)
		{
			std::cerr << "Recv failed or connection closed" << std::endl;
			break;
		}

		recvBuf[recvLen] = '\0';
		std::cout << "\nServer replied: " << recvBuf << std::endl;
	}

	client.disconnect();
	WSACleanup();
	return 0;
}