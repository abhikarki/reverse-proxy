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
	std::cout << "Commands: 'ratelimit_test' to test rate limiting, 'exit' to quit\n" << std::endl;

	
	char recvBuf[4096];
	while(true){
		std::string msg;
		std::cout << "Enter message: ";
		std::getline(std::cin, msg);

		if(msg == "exit") break;

		if(msg == "ratelimit_test"){
			std::cout << "\n ==Rate Limit Test--" << std::endl;
			std::cout << "Sending 120 rapid requests to trigger rate limiting" << std::endl;

			int allowed = 0;
			int blocked = 0;
			for(int i = 1; i <= 120; i++){
				std::string testMsg = "Request " + std::to_string(i) + "\n";
				int sent = send(clientSocket, testMsg.c_str(), (int)testMsg.size(), 0);
				if(sent == SOCKET_ERROR){
					std::cerr << "send failed at request" << i << std::endl;
					break;
				}

				int recvLen = recv(clientSocket, recvBuf, sizeof(recvBuf) - 1, 0);
				if(recvLen <= 0){
					std::cerr << "Server closed connection at request" << i << std::endl;
					break;
				}
				recvBuf[recvLen] = '\0';

				std::string response(recvBuf);
				if(response.find("429") != std::string::npos){
					blocked++;
					if(blocked == 1){
						std::cout << "First 429 at request " << i << std::endl;
					}
					else{
						allowed++;
					}

					//  progress 
				if(i % 20 == 0){
					std::cout << "Progress: " << i << "/120 (Allowed: " << allowed << ", Blocked: " << blocked << ")" << std::endl;
				}
				}
				
				std::cout << "\n=== Results ===" << std::endl;
				std::cout << "Total Allowed: " << allowed << std::endl;
				std::cout << "Total Blocked (429): " << blocked << std::endl;
				std::cout << "================\n" << std::endl;
				continue;
				
			}
		}
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