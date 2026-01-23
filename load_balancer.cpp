#include "load_balancer.h"
#include <algorithm>
#include <sstream>
#include <random>
#include <cstring>
#include <mutex>

namespace LoadBalance{
uint32_t hashIP(const std::string& ip){
    // using unsigned integer so it wraps after overflow
    uint32_t hash = 5381;
    for(char c : ip){
        hash = ((hash << 5) + hash) + static_cast<unsigned char>(c);
    }
    return hash;
}

BackendPool::BackendPool(const std::string& poolName, const PoolConfig& cfg) : name(poolName), config(cfg), roundRobinIndex(0) {}

void BackendPool::addBackend(const std::string& host, unsigned short port, int weight){
    std::unique_lock lock(mutex);
    backends.emplace_back(host, port);
    weights.push_back(weight);
}

bool BackendPool::removeBackend(const std::string& host, unsigned short port){
    std::unique_lock loc(mutex);
    for(size_t i = 0; i < backends.size(); i++){
        if(backends[i].host == host && backends[i].port == port){
            backends.erase(backends.begin() + i);
            weights.erase(weights.begin() + i);
            return true;
        }
    }
    return false;
}

size_t BackendPool::selectRoundRobin(){
    if(backends.empty()) return SIZE_MAX;

    size_t attempts = backends.size();
    while(attempts-- > 0){
        size_t idx = roundRobinIndex.fetch_add(1) % backends.size();
        if(backends[idx].healthy.load()){
            return idx;
        }
    }
    // no healthy backend
    return SIZE_MAX;
}

size_t BackendPool::selectLeastConnections(){
    if(backends.empty()) return SIZE_MAX;

    size_t bestIdx = SIZE_MAX;
    int minConnections = INT_MAX;

    for(size_t i = 0; i < backends.size(); i++){
        if(backends[i].healthy.load()){
            int conn = backends[i].activeConnections.load();
            if(conn < minConnections){
                minConnections = conn;
                bestIdx = i;
            }
        }
    }
    return bestIdx;
}

size_t BackendPool::selectWeightedRoundRobin(){
    if(backends.empty()) return SIZE_MAX;

    int totalWeight = 0;
    for(size_t i = 0; i < backends.size(); i++){
        if(backends[i].healthy.load()){
            totalWeight += weights[i];
        }
    }

    if(totalWeight == 0) return SIZE_MAX;

    size_t idx = roundRobinIndex.fetch_add(1);
    int target = idx % totalWeight;
    int cumulative = 0;

    for(size_t i = 0; i < backends.size(); i++){
        if(backends[i].healthy.load()){
            cumulative += weights[i];
            if(target < cumulative){
                return i;
            }
        }
    }

    // fallback... the above logic could fail if some turned unhealthy between the two loops
    for(size_t i = 0; i < backends.size(); i++){
        if(backends[i].healthy.load()) return;
    }
    return SIZE_MAX;
}

size_t BackendPool::selectIPHash(const std::string& clientIP){
    if(backends.empty()) return SIZE_MAX;

    std::vector<size_t> healthyIndices;

    for(size_t i = 0; i < backends.size(); i++){
        if(backends[i].healthy.load()){
            healthyIndices.push_back(i);
        }
    }

    if(healthyIndices.empty()) return SIZE_MAX;

    // this is not so sticky, as a single server being down can reorder everything... later, consistent hashing (like a hash Ring ) can be used
    uint32_t hash = hashIP(clientIP);
    return healthyIndices[hash % healthyIndices.size()];
}

size_t BackendPool::selectRandom(){
    if(backends.empty()) return SIZE_MAX;

    std::vector<size_t> healthyIndices;
    for(size_t i = 0; i < backends.size(); i++){
        if(backends[i].healthy.load()){
            healthyIndices.push_back(i);
        }
    }

    if(healthyIndices.empty()) return SIZE_MAX;

    static thread_local std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<size_t> dist(0, healthyIndices.size() - 1);
    return healthyIndices[dist(gen)];
}

Backend* BackendPool::selectBackend(const std::string& clientIP){
    std::shared_lock lock(mutex);

    if(backends.empty()) return nullptr;

    size_t idx = SIZE_MAX;

    switch(config.algorithm){
        case Algorithm::ROUND_ROBIN:
            idx = selectRoundRobin();
            break;
        case Algorithm::LEAST_CONNECTIONS:
            idx = selectLeastConnections();
            break;
        case Algorithm::WEIGHTED_ROUND_ROBIN:
            idx = selectWeightedRoundRobin();
            break;
        case Algorithm::IP_HASH:
            idx = selectIPHash(clientIP);
            break;
        case Algorithm::RANDOM:
            idx = selectRandom();
            break;
    }

    if(idx == SIZE_MAX) return nullptr;
    return &backends[idx];
}

void BackendPool::requestStarted(Backend* backend){
    if(backend){
        backend->activeConnections.fetch_add(1);
        backend->totalRequests.fetch_add(1);
    }
}

void BackendPool::requestCompleted(Backend* backend, bool success){
    if(backend){
        backend->activeConnections.fetch_sub(1);
        if(!success){
            backend->failedRequests.fetch_add(1);
        }
    }
}

void BackendPool::setBackendHealth(Backend* backend, bool healthy){
    if(backend){
        backend->healthy.store(healthy);
        backend->lastHealthCheck = std::chrono::steady_clock::now();
    }
}

std::vector<Backend*> BackendPool::getAllBackends(){
    std::shared_lock lock(mutex);
    std::vector<Backend*> result;
    for(auto& backend : backends){
        result.push_back(&backend);
    }
    return result;
}

size_t BackendPool::getHealthyCount() const{
    std::shared_lock lock(mutex);
    size_t count = 0;
    for(const auto& backend : backends){
        if(backend.healthy.load()) count++;
    }
    return count;
}

size_t BackendPool::getTotalCount() const{
    std::shared_lock lock(mutex);
    return backends.size();
}

std::string BackendPool::getStats() const{
    std::shared_lock lock(mutex);
    std::ostringstream oss;
    oss << "Pool: " << name << " ()";
    oss << getHealthyCount() << "/" << backends.size() << " healthy)\n";

    for(const auto& backend : backends){
        oss << " " << backend.getAddress();
        oss << "  [" << (backend.healthy.load() ? "UP" : "DOWN") << "]";
         oss << " active=" << backend.activeConnections.load();
        oss << " total=" << backend.totalRequests.load();
        oss << " failed=" << backend.failedRequests.load();
        oss << "\n";
    }
    return oss.str();
}

LoadBalancer::LoadBalancer() {}

BackendPool& LoadBalancer::createPool(const std::string& name, const PoolConfig& config){
    std::unique_lock lock(mutex);
    auto result = pools.emplace(name, BackendPool(name, config));
    return result.first->second;
}

BackendPool* LoadBalancer::getPool(const std::string& name){
    std::shared_lock lock(mutex);
    auto it = pools.find(name);
    if(it != pools.end()){
        return &it->second;
    }
    return nullptr;
}

void LoadBalancer::addRoute(const Route& route){
    std::unique_lock lock(mutex);
    routes.push_back(route);

    // by priority, then by path length (long to short)
    std::sort(routes.begin(), routes.end(), [](const Route& a, const Route& b){
        if(a.priority != b.priority) return a.priority > b.priority;
        return a.pathPrefix.length() > b.pathPrefix.length();
    });
}

void LoadBalancer::setDefaultPool(const std::string& poolName){
    std::unique_lock lock(mutex);
    defaultPoolName = poolName;
}

BackendPool* LoadBalancer::routeRequest(const std::string& host, const std::string& path){
    std::shared_lock lock(mutex);

    for(const auto& route : routes){
        bool hostMatch = route.hostPattern == "*" || route.hostPattern == host || (route.hostPattern.empty());
        bool pathMatch = path.find(route.pathPrefix);

        if(hostMatch && pathMatch){
            auto it = pools.find(route.poolName);
            if(it != pools.end()){
                return &it->second;
            }
        }
    }

    if(!defaultPoolName.empty()){
        auto it = pools.find(defaultPoolName);
        if(it != pools.end()){
            return &it->second;
        }
    }
    return nullptr;
}

Backend* LoadBalancer::selectBackendForRequest(const std::string& host, const std::string& path, const std::string& clientIP){
    BackendPool* pool = routeRequest(host, path);
    if(!pool) return nullptr;
    return pool->selectBackend(clientIP);
}

std::string LoadBalancer::getAllStats() const{
    std::shared_lock lock(mutex);
    std::ostringstream oss;
    oss << "Load Balancer Stats: \n";
    oss << "Routes: " << routes.size() << "\n";
    oss << "Default pool: " << (defaultPoolName.empty() ? "(none)" : defaultPoolName) << "\n\n";

    for(const auto& pair : pools){
        oss << pair.second.getStats() << "\n";
    }
    return oss.str();
}

}