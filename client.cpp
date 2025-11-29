#include "stdafx.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include "iostream"

#pragma comment(lib, "Ws2_32.lib");

int main(int argc, char *argv[]) {
	SOCKET clientSocket;
	int port = 5555;
	WSADATA wsaData;
	int wsaerr;
	WORD wVersionRequested = MAKEWORD(2, 2);
	wsaerr = WSAStartup(wVersionRequested, &wsaData);
	if (wsaerr != 0) {
		std::cout << "winsock initialization failed." << std::endl;
		return 0;
	}
	else {
		std::cout << "winsock initialized." << std::endl;
		std::cout << "Status: " << wsaData.szSystemStatus << std::endl;
	}

	clientSocket = INVALID_SOCKET;
	clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (clientSocket == INVALID_SOCKET) {
		std::cout << "Error while creating client socket." << WSAGetLastError() << std::endl;
		WSACleanup();
		return 0;
	}
	else {
		std::cout << "clientSocket formed success." << std::endl;
	}

	// connecting the client, should match the server IP address and port.
	sockaddr_in clientService;
	clientService.sin_family = AF_INET;
	InetPton(AF_INET, _T("127.0.0.1"), &clientService.sin_addr.s_addr);
	clientService.sin_port = htons(port);    // Server port
	if (connect(clientSocket, (SOCKADDR*)&clientService, sizeof(clientService)) == SOCKET_ERROR) {
		std::cout << "Failed to connect to server" << std::endl;
		WSACleanup();
		return 0; 
	}
	else {
		std::cout << "Client connection success" << std::endl;
	}
	system("pause");
	WSACleanup();
	return 0;
}