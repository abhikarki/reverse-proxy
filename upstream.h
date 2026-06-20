#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <string>
#include <memory>

namespace Upstream{
    class Connection{
        private:
            SOCKET socket;
            std::string host;
            unsigned short port;
            bool connected;
        public:
            Connection(const std::string& h, unsigned short p);
            ~Connection();

            bool initiateAsyncConnect(HANDLE iocp);

            SOCKET getSocket() const { return socket; }

            bool isConnected() const { return connected; }

            void markConnected() { connected = true; }

            std::string getAddress() const{
                return host + ":" + std::to_string(port);
            }

            void close();

            SOCKET release();
    };
}