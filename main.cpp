#include "stdafx.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include "iostream"

#pragma comment(lib, "Ws2_32.lib");

int main(int argc, char *argv[]) {
	SOCKET serverSocket, acceptSocket;
	int port = 5555;
	WSADATA wsaData;
	int wsaerr;
	WORD wVersionRequested = MAKEWORD(2, 2);
	wserr = WSAStartup(wVersionRequested, &wsaData);
	if (wsaerr != 0) {
		std::cout << "Winsock dll not found" << std::endl;
		return 0;
	}
	else {
		std::cout << "Winsock dll found" << endl;
		std::cout << "Status: " << wsaData.szSystemStatus << std::endl;
	}
	return 0;

	serverSocket = INVALID_SOCKET;
	serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (serverSocket == INVALID_SOCKET) {
		std::cout << "Error at socket(): " << WSAGetLastError() << std::endl;
		WSACleanup();
		return 0;
	}
	else {
		std::cout << "socket (unbounded) setup success" << std::endl;
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