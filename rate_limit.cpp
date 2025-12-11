#include "proxy.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <mswsock.h>
#include <mutex>
#include <cmath>


namespace RateLimit{

    TokenBucket::TokenBucket(double initial) : tokens(initial), lastRefill(std::chrono::steady_clock::now()){}

    Limiter::Limiter(const Config& cfg) : config(cfg){}

    void Limiter::refillBucket(TokenBucket& bucket){
        auto now = std::chrono::steady_clock::now();

        std::chrono::duration<double> elapsed = now - bucket.lastRefill;
        double seconds = elapsed.count();
  
        if(seconds > 0){
            double newTokens = seconds * config.refillRate;
            bucket.tokens = std::min(config.maxTokens, bucket.tokens + newTokens);
            bucket.lastRefill = now;
        }
    }

    bool Limiter::allowRequest(const std::string& clientIP){
        // if rate limiting is disabled
        if(!config.enabled) return true;

        // scoped block to immediately release the locks when we go out of it
        {
            std::shared_lock<std::shared_mutex> readLock(mutex);
            auto it = buckets.find(clientIP);
            if(it != buckets.end()){
                // releasing the read lock to use the write lock
                readLock.unlock();

                std::unique_lock<std::shared_mutex> writeLock(mutex);
                // double checking to make sure it was not removed in between.
                auto it2 = buckets.find(clientIP);
                if(it2 != buckets.end()){
                    refillBucket(it2 -> second);

                    if(it2->second.tokens >= 1.0){
                        it2->second.tokens -= 1.0;
                        return true;
                    }
                    return false;          // else rate limited
                }

            }
        }

        // creating the bucket if it doesnot exist
        std::unique_lock<std::shared_mutex> writeLock(mutex);

        // double check to make sure
        auto it = buckets.find(clientIP);
        if(it != buckets.end()){
            refillBucket(it->second);
            if(it->second.tokens >= 1.0){
                it->second.tokens -= 1.0;
                return true;
            }
            return false;
        }
        buckets.emplace(clientIP, TokenBucket(config.maxTokens - 1.0));
        return true;
    }


    double Limiter::getRemainingTokens(const std::string& clientIP){
        // first acquiring the read lock
        std::shared_lock<std::shared_mutex> lock(mutex);

        auto it = buckets.find(clientIP);
        // If client doesnot exist, we just return the max tokens.
        if(it == buckets.end()){
            return config.maxTokens;
        }

        // Here, we are not updating the tokens based on the time elapsed to keep this simple and efficient
        return std::max(0.0, it->second.tokens);
    }

    double Limiter::getRetryAfter(const std::string& clientIP){
        // acquiring the read lock
        std::shared_lock<std::shared_mutex> lock(mutex);

        auto it = buckets.find(clientIP);
        // if the client doesnot already exist, no wait is needed.
        if(it == buckets.end()){
            return 0.0;
        }

        // if client has at least one token, no wait needed.
        if(it->second.tokens >= 1.0){
            return 0.0;
        }

        // calculating the waiting time.
        double tokensNeeded = 1.0 - it->second.tokens;
        double secondsToWait = tokensNeeded / config.refillRate;

        return std::ceil(secondsToWait);
    }

    void Limiter::cleanup(int maxAgeSeconds){
        // acquire the write lock
        std::unique_lock<std::shared_mutex> lock(mutex);

        auto now = std::chrono::steady_clock::now();
        auto maxAge = std::chrono::seconds(maxAgeSeconds);

        for(auto it = buckets.begin(); it != buckets.end()){
            auto age = now - it->second.lastRefill;
            if(age > maxAge){
                // std::map::erase deletes and returns the pointer to the next one
                it = buckets.erase(it);  
            }
            else{
                ++it;
            }
        }
    }

    std::string build429Response(double retryAfter, double limit, double remaining){
        std::ostringstream response;

        response << "HTTP/1.1 429 Too Many Requests\r\n";
        response << "Content-Type: text/plain\r\n";
        response << "Connection: close\r\n";
        response << "Retry-After: " << static_cast<int>(retryAfter) << "\r\n";
        response << "X-RateLimit-Limit: " << static_cast<int>(limit) << "\r\n";
        response << "\r\n";          // separating the header
        response << "Rate limit exceeded. Please retry later" << static_cast<int>(retryAfter) << " seconds. \r\n";
        
        return response.str();
    }

}

namespace ProxyUtil{
    std::string getClientIP(SOCKET sock){
        sockaddr_in addr;
        int addrLen = sizeof(addr);

        if(getpeername(sock, (sockaddr*)&addr, &addrLen) == 0){
            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr.sin_addr, ipStr, INET_ADDRSTRLEN);
            return std::string(ipStr);
        }
        return "unknown";
    }

    std::string getClientIPFromAcceptEx(
        SOCKET listenSocket,
        char* buffer,
        DWORD localAddrLen,
        DWORD remoteAddrLen
    ){
        // pointer type for the extension function 
        typedef void (PASCAL *LPFN_GETACCEPTEXSOCKADDRS)(
            PVOID lpOutputBuffer,
            DWORD dwReceiveDataLength,
            DWORD dwLocalAddressLength,
            DWORD dwRemoteAddressLength,
            LPSOCKADDR* LocalSockaddr,
            LPINT LocalSockaddrLength,
            LPSOCKADDR* RemoteSockaddr,
            LPINT RemoteSockaddrLength
        );

        // declaring static for lazy initialization
        static LPFN_GETACCEPTEXSOCKADDRS s_GetAcceptExSockaddrs = nullptr;

        // lazy initialization
        if(!s_GetAcceptExSockaddrs){
            GUID guidGetAcceptExSockaddrs = WSAID_GETACCEPTEXSOCKADDRS;
            DWORD bytes = 0;

            WSAIoctl(
                listenSocket,
                SIO_GET_EXTENSION_FUNCTION_POINTER,
                &guidGetAcceptExSockaddrs,
                sizeof(guidGetAcceptExSockaddrs),
                &s_GetAcceptExSockaddrs,
                sizeof(s_GetAcceptExSockaddrs),
                &bytes,
                nullptr,
                nullptr
            );
        }

        if(!s_GetAcceptExSockaddrs) return "unknown";

        sockaddr* localAddr = nullptr;
        sockaddr* remoteAddr = nullptr;
        int localAddrSize = 0;
        int remoteAddrSize = 0;

        s_GetAcceptExSockaddrs(
            buffer,
            0,
            localAddrLen,
            remoteAddrLen,
            &localAddr,
            &localAddrSize,
            &remoteAddr,
            &remoteAddrSize
        );

        // if remoteAddr is not null and it is an IPv4 address
        if(remoteAddr && remoteAddr->sa_family == AF_INET){
            // casting to sockaddr_in since we have verified it as IPv4, so safe.
            sockaddr_in*addr = reinterpret_cast<sockaddr_in*>(remoteAddr);
            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr->sin_addr, ipStr, INET_ADDRSTRLEN);
            return std::string(ipStr)l
        }
        return "unknown";
    }
}