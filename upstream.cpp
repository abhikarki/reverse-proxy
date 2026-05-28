#include "upstream.h"
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

namespace Upstream{
    Connection::Connection(const std::string& h, unsigned short p) : host(h), port(p), connected(false)
    {
        socket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
        if(socket == INVALID_SOCKET){
            int err = WSAGetLastError();
            std::cerr << "Failed to create upstream socket: " << err << std::endl;
        }
    }

    Connection::~Connection(){
        close();
    }

    bool Connection::initiateAsyncConnect(HANDLE iocp){
        if(socket == INVALID_SOCKET){
            std::cerr << "Socket is invalid" << std::endl;
            return false;
        }

        HANDLE result = CreateIoCompletionPort((HANDLE)socket, iocp, (ULONG_PTR)socket, 0);
        if(!result){
            int err = GetLastError();
            std::cerr << "Failed to associate upstream socket with IOCP: " << err << std::endl;
            return false;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        int rc = inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
        if(rc != 1){
            std::cerr << "Failed to parse backend host: " << host << std::endl;
            return false;
        }

        LPFN_CONNECTEX lpfnConnectEx = nullptr;
        GUID guidConnectEx = WSAID_CONNECTEX;
        DWORD bytes = 0;

        rc = WSAIoctl(
            socket,
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
            int err = WSAGetLastError();
            std::cerr << "Failed to get ConnectEx function pointer: " << err << std::endl;
            return false;
        }

        sockaddr_in localAddr{};
        localAddr.sin_family = AF_INET;
        localAddr.sin_addr.s_addr = INADDR_ANY;
        localAddr.sin_port = 0;

        if(bind(socket, (sockaddr*)&localAddr, sizeof(localAddr)) == SOCKET_ERROR){
            int err = WSAGetLastError();
            std::cerr << "Failed to bind upstream socket: " << err << std::endl;
            return false;
        }

        return true;
    }

    void Connection::close(){
        if(socket != INVALID_SOCKET){
            shutdown(socket, SD_BOTH);
            closesocket(socket);
            socket = INVALID_SOCKET;
        }
        connected = false;
    }

    SOCKET Connection::release(){
        SOCKET s = socket;
        socket = INVALID_SOCKET;
        return s;
    }
}