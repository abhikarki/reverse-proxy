#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock.h>
#include <ws2tcpip.h>
#include <string>
#include <unordered_map>
#include <chrono>
#include <shared_mutex>
#include <atomic>
#include <vector>


namespace RateLimit{
    // Configuration for the rate limiter
    struct Config{
        double maxTokens;
        double refillRate;
        bool enabled;

        Config(double max = 100.0, double rate = 10.0, bool on = true) : maxTokens(max), refillRate(rate), enabled(on){}
    };

    // for single client
    struct TokenBucket{
        double tokens;                                     //current tokens
        std::chrono::steady_clock::time_point lastRefill;  // last refill time

        TokenBucket(double initial);
    };

    // rate limiter
    class Limiter{
    private:
        Config config;
        std::unordered_map<std::string, TokenBucket> buckets;
        mutable std::shared_mutex mutex;     // to provide Reader Writer lock
    
    public:
        // constructor with our default config
        explicit Limiter(const Config& cfg = Config());
        
        // check if the request is allowed for the client
        bool allowRequest(const std::string& clientIP);

        // return the token count
        double getRemainingTokens(const std::string& clientIP);

        // get time that client must wait until a token in available
        double getRetryAfter(const std::string& clientIP);

        // cleanup to remove inactive clients, freeing up memory
        void cleanup(int maxAgeSeconds = 3600);

        // to access current config settings
        const Config& getConfig() const;
    };

    // to build HTTP 429-rate limited response
    std::string build429Response(double retryAfter, double limit, double remaining);
}

namespace ProxyUtil{
    // get client's IP
    std::string getClientIP(SOCKET sock);

    // get client's IP from AcceptEx buffer using GetAcceptExSockaddrs
    std:: string getClientIPFromAcceptEx(
        SOCKET listenSocket,
        char* buffer,
        DWORD localAddrLen,
        DWORD remoteAddrLen
    );
}