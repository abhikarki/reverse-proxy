#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include "iostream"

// #pragma comment(lib, "Ws2_32.lib");

int main(int argc, char *argv[]) {
	WSADATA wsaData;
	if(WSAStartup(MAKEWORD(2,2), &wsaData) != 0){
		std::cerr << "WSAStartup failed" << std::endl;
		return 1;
	}

	SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(clientSocket == INVALID_SOCKET){
		std::cerr << "socket failed" << std::endl;
		WSACleanup();
		return 1;
	}

	sockaddr_in server{};
	server.sin_family = AF_INET;
	server.sin_port = htons(8080);
	inet_pton(AF_INET, "127.0.0.1", &server.sin_addr);

	if(connect(clientSocket, (sockaddr*)&server, sizeof(server)) == SOCKET_ERROR){
		std::cerr << "connect failed" << std::endl;
		closesocket(clientSocket);
		WSACleanup();
		return 1;
	}

	std::cout << "Connected to Server" << std::endl;
	
	char recvBuf[4096];
	while(true){
		std::string msg;
		std::cout << ">";
		std::getline(std::cin, msg);

		if(msg == "exit") break;
		msg.push_back('\n');
		int sent = send(clientSocket, msg.c_str(), (int)msg.size(), 0);
		if(sent == SOCKET_ERROR){
			std::cerr << "send failed " << WSAGetLastError() << std::endl;
			break;
		}

		int recvLen = recv(clientSocket, recvBuf, sizeof(recvBuf) - 1, 0);
		if(recvLen <= 0){
			std::cerr << "Server closed connection" << std::endl;
			break; 
		}
		

		recvBuf[recvLen] = '\0';
        std::cout << "Server replies: " << recvBuf << std::endl;
	}
	
	std::cout << "closing" << std::endl;
	closesocket(clientSocket);
	WSACleanup();
	return 0;
}