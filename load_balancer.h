#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <atomic>
#include <shared_mutex>
#include <chrono>
#include <optional>
#include <memory>

namespace LoadBalance
{

    // a single backend server representation
    struct Backend
    {
        std::string host;
        unsigned short port;
        std::atomic<bool> healthy;
        std::atomic<int> activeConnections;
        std::atomic<uint64_t> totalRequests;
        std::atomic<uint64_t> failedRequests;
        std::chrono::steady_clock::time_point lastHealthCheck;

        Backend(const std::string &h, unsigned short p) : host(h), port(p), healthy(true), activeConnections(0), totalRequests(0), failedRequests(0), lastHealthCheck(std::chrono::steady_clock::now()) {}

        // Copy constructor
        Backend(const Backend &other) : host(other.host), port(other.port), healthy(other.healthy.load()), activeConnections(other.activeConnections.load()), totalRequests(other.totalRequests.load()), failedRequests(other.failedRequests.load()), lastHealthCheck(other.lastHealthCheck) {}

        // Move constructor
        Backend(Backend &&other) noexcept : host(std::move(other.host)), port(other.port), healthy(other.healthy.load()), activeConnections(other.activeConnections.load()), totalRequests(other.totalRequests.load()), failedRequests(other.failedRequests.load()), lastHealthCheck(other.lastHealthCheck) {}

        // Copy assignment
        Backend &operator=(const Backend &other)
        {
            if (this != &other)
            {
                host = other.host;
                port = other.port;
                healthy.store(other.healthy.load());
                activeConnections.store(other.activeConnections.load());
                totalRequests.store(other.totalRequests.load());
                failedRequests.store(other.failedRequests.load());
                lastHealthCheck = other.lastHealthCheck;
            }
            return *this;
        }

        // Move assignment
        Backend &operator=(Backend &&other) noexcept
        {
            if (this != &other)
            {
                host = std::move(other.host);
                port = other.port;
                healthy.store(other.healthy.load());
                activeConnections.store(other.activeConnections.load());
                totalRequests.store(other.totalRequests.load());
                failedRequests.store(other.failedRequests.load());
                lastHealthCheck = other.lastHealthCheck;
            }
            return *this;
        }

        std::string getAddress() const
        {
            return host + ":" + std::to_string(port);
        }
    };

    enum class Algorithm
    {
        ROUND_ROBIN,
        LEAST_CONNECTIONS,
        WEIGHTED_ROUND_ROBIN,
        IP_HASH,
        RANDOM
    };

    struct PoolConfig
    {
        Algorithm algorithm;
        int healthCheckIntervalSeconds;
        int healthCheckTimeoutMs;
        int maxFailures;
        bool enabled;

        PoolConfig() : algorithm(Algorithm::ROUND_ROBIN), healthCheckIntervalSeconds(30), healthCheckTimeoutMs(5000), maxFailures(3), enabled(true) {}
    };

    class BackendPool
    {
    private:
        std::string name;
        std::vector<Backend> backends;
        std::vector<int> weights;
        PoolConfig config;
        std::atomic<size_t> roundRobinIndex;
        mutable std::shared_mutex mutex;

        size_t selectRoundRobin();
        size_t selectLeastConnections();
        size_t selectWeightedRoundRobin();
        size_t selectIPHash(const std::string &clientIP);
        size_t selectRandom();

    public:
        explicit BackendPool(const std::string &poolName, const PoolConfig &cfg = PoolConfig());

        // Move semantics
        BackendPool(BackendPool &&) = default;
        BackendPool &operator=(BackendPool &&) = default;

        // Delete copy semantics
        BackendPool(const BackendPool &) = delete;
        BackendPool &operator=(const BackendPool &) = delete;

        void addBackend(const std::string &host, unsigned short port, int weight = 1);

        bool removeBackend(const std::string &host, unsigned short port);

        Backend *selectBackend(const std::string &clientIP = "");

        void requestStarted(Backend *backend);

        void requestCompleted(Backend *backend, bool success);

        void setBackendHealth(Backend *backend, bool healthy);

        std::vector<Backend *> getAllBackends();

        size_t getHealthyCount() const;

        size_t getTotalCount() const;

        const std::string &getName() const { return name; }

        std::string getStats() const;
    };

    struct Route
    {
        std::string pathPrefix;
        std::string hostPattern;
        std::string poolName;
        int priority;

        Route(const std::string &path, const std::string &host, const std::string &pool, int priority = 0) : pathPrefix(path), hostPattern(host), poolName(pool), priority(priority) {}
    };

    class LoadBalancer
    {
    private:
        std::unordered_map<std::string, std::unique_ptr<BackendPool>> pools;
        std::vector<Route> routes;
        std::string defaultPoolName;
        mutable std::shared_mutex mutex;

    public:
        LoadBalancer();

        BackendPool &createPool(const std::string &name, const PoolConfig &config = PoolConfig());

        BackendPool *getPool(const std::string &name);

        void addRoute(const Route &route);

        void setDefaultPool(const std::string &poolName);

        BackendPool *routeRequest(const std::string &host, const std::string &path);

        Backend *selectBackendForRequest(const std::string &host, const std::string &path, const std::string &clientIP = "");

        std::string getAllStats() const;
    };

    uint32_t hashIP(const std::string &ip);
}