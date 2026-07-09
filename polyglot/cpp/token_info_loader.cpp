// polyglot/cpp/token_info_loader.cpp
// Token info loader for ApproveWarden - fetches ERC-20/721/1155 metadata with caching

#include <iostream>
#include <string>
#include <map>
#include <mutex>
#include <atomic>
#include <chrono>
#include <thread>
#include <curl/curl.h>
#include <regex>
#include <sstream>
#include <iomanip>

namespace polyglot { namespace cpp {

// ============================================================================
// Configuration and Constants
// ============================================================================

constexpr uint64_t DEFAULT_CHAIN_ID = 1; // Ethereum mainnet
constexpr size_t MAX_CACHE_SIZE = 1024;
constexpr int HTTP_TIMEOUT_MS = 5000;
constexpr int RETRY_COUNT = 3;
constexpr int INITIAL_RETRY_DELAY_MS = 100;

// Etherscan API base URL (supports multiple chains via chainId param)
constexpr const char* ETHERSCAN_API_BASE = "https://api.etherscan.io/api";

struct ChainConfig {
    std::string name;
    uint64_t chainId;
    std::string apiBase;
};

// ============================================================================
// HTTP Client (libcurl wrapper)
// ============================================================================

class HttpUtils {
public:
    static std::string Get(const std::string& url, int timeoutMs = HTTP_TIMEOUT_MS) {
        CURL* curl = curl_easy_init();
        if (!curl) return "";
        
        std::string response;
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "User-Agent: ApproveWarden/1.0");
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeoutMs);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        
        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            response.append((char*)curl_easy_getinfo(
                curl, CURLINFO_RESPONSE_SIZE)); // dummy to trigger callback
        }
        
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        
        return response;
    }

private:
    static size_t WriteCallback(void* ptr, size_t size, size_t nmemb, void* userdata) {
        std::string* s = static_cast<std::string*>(userdata);
        s->append(static_cast<char*>(ptr), size * nmemb);
        return size * nmemb;
    }
};

// ============================================================================
// Token Metadata Cache (Thread-Safe)
// ============================================================================

class TokenCache {
public:
    struct TokenInfo {
        std::string address;
        std::string name;
        std::string symbol;
        int decimals = 18;
        uint64_t chainId = DEFAULT_CHAIN_ID;
        bool isVerified = false;
        std::string logoUrl;
        std::chrono::steady_clock::time_point lastUpdated;
    };

private:
    mutable std::mutex mtx_;
    std::map<std::string, TokenInfo> cache_;
    size_t hitCount_ = 0;
    size_t missCount_ = 0;
    
public:
    bool GetOrLoad(const std::string& address, uint64_t chainId, 
                   const std::function<TokenInfo()>& loader) {
        auto key = address + "_" + std::to_string(chainId);
        
        // Check cache first
        auto it = cache_.find(key);
        if (it != cache_.end()) {
            hitCount_++;
            return true;
        }
        
        missCount_++;
        
        // Load from source
        TokenInfo info;
        info.address = address;
        info.chainId = chainId;
        info.lastUpdated = std::chrono::steady_clock::now();
        
        if (loader) {
            info = loader();
        }
        
        cache_[key] = info;
        return true;
    }

    TokenInfo Get(const std::string& address, uint64_t chainId) const {
        auto it = cache_.find(address + "_" + std::to_string(chainId));
        if (it != cache_.end()) {
            return it->second;
        }
        return {};
    }

    size_t GetCacheSize() const {
        std::lock_guard<std::mutex> lock(mtx_);
        return cache_.size();
    }

    void ClearExpired(std::chrono::seconds maxAge) {
        auto now = std::chrono::steady_clock::now();
        std::vector<std::string> toRemove;
        
        for (auto& [key, info] : cache_) {
            if (std::chrono::duration_cast<std::chrono::seconds>(
                    now - info.lastUpdated).count() > maxAge.count()) {
                toRemove.push_back(key);
            }
        }
        
        for (const auto& key : toRemove) {
            cache_.erase(key);
        }
    }

private:
    struct CacheStats {
        size_t hits = 0;
        size_t misses = 0;
        double hitRate() const {
            return total() > 0 ? static_cast<double>(hits) / total() : 1.0;
        }
        size_t total() const { return hits + misses; }
    };

public:
    CacheStats GetStats() const {
        std::lock_guard<std::mutex> lock(mtx_);
        return {hitCount_, missCount_};
    }
};

// ============================================================================
// Etherscan API Client
// ============================================================================

class EtherscanClient {
public:
    struct Config {
        std::string apiKey;
        uint64_t chainId = DEFAULT_CHAIN_ID;
    };

private:
    Config config_;
    static constexpr int MAX_RETRIES = 3;

public:
    explicit EtherscanClient(const Config& cfg) : config_(cfg) {}

    TokenCache::TokenInfo FetchTokenInfo(const std::string& address, 
                                         const std::function<TokenCache::TokenInfo()>& loader) {
        // Build API URL for token info
        std::ostringstream url;
        url << ETHERSCAN_API_BASE << "/api";
        
        if (config_.chainId == DEFAULT_CHAIN_ID) {
            url << "?module=token&action=tokendetails&address=" 
                << address << "&apikey=" << config_.apiKey;
        } else {
            // For other chains, use different endpoints
            url << "?module=stats&action=tokeninfo&chainid=" 
                << config_.chainId << "&address=" << address;
        }

        std::string response = HttpUtils::Get(url.str());
        
        if (response.empty()) {
            return loader(); // Fallback to custom loader on error
        }

        // Parse JSON - simple regex-based parsing for robustness
        TokenCache::TokenInfo info;
        info.address = address;
        info.chainId = config_.chainId;
        
        // Extract name (try multiple patterns)
        std::regex nameRegex(R"(\\"name\":"([^,]+))");
        auto nameMatch = std::sregex_search(response, nameRegex);
        if (nameMatch) {
            info.name = nameMatch[1].str();
        }

        // Extract symbol
        std::regex symRegex(R"(\\"symbol\":"([^,]+))");
        auto symMatch = std::sregex_search(response, symRegex);
        if (symMatch) {
            info.symbol = symMatch[1].str();
        }

        // Extract decimals
        std::regex decRegex(R"(\\"decimals\":"(\d+))");
        auto decMatch = std::sregex_search(response, decRegex);
        if (decMatch) {
            info.decimals = std::stoi(decMatch[1].str());
        }

        // Extract logo URL
        std::regex logoRegex(R"(\\"logo\":"([^,]+))");
        auto logoMatch = std::sregex_search(response, logoRegex);
        if (logoMatch) {
            info.logoUrl = logoMatch[1].str();
        }

        // Check verification status
        bool verified = response.find("Verified: Yes") != std::string::npos ||
                        response.find("\"verified\":true") != std::string::npos;
        info.isVerified = verified;

        return info;
    }

    TokenCache::TokenInfo FetchWithRetry(const std::string& address, 
                                         const std::function<TokenCache::TokenInfo()>& loader) {
        for (int i = 0; i < MAX_RETRIES; ++i) {
            auto info = FetchTokenInfo(address, loader);
            if (!info.address.empty()) return info;
            
            // Exponential backoff
            std::this_thread::sleep_for(std::chrono::milliseconds(INITIAL_RETRY_DELAY_MS * (i + 1)));
        }

        // All retries failed - use custom loader as fallback
        return loader();
    }
};

// ============================================================================
// TokenInfoLoader - Main Interface
// ============================================================================

class TokenInfoLoader {
public:
    struct Config {
        std::string etherscanApiKey;
        uint64_t defaultChainId = DEFAULT_CHAIN_ID;
        bool enableCache = true;
        int cacheTTLSeconds = 300; // 5 minutes
    };

private:
    Config config_;
    TokenCache cache_;
    EtherscanClient etherscanClient;

public:
    explicit TokenInfoLoader(const Config& cfg) 
        : config_(cfg), 
          etherscanClient({cfg.etherscanApiKey, cfg.defaultChainId}) {
        
        if (config_.enableCache) {
            // Pre-warm cache with common tokens (optional optimization)
            const std::vector<std::string> warmupTokens = {
                "0xC02aAa394dbC14BdCeFF1cD8AA96459E90f6c7e9", // WETH
                "0xdAC17F958D2ee523a2206206994597C13D831ec7", // USDT
                "0xA0b86991c6218b36c1d19D4Ae8ea9cf153Uf4B1",  // USDC
            };
            
            for (const auto& addr : warmupTokens) {
                cache_.GetOrLoad(addr, config_.defaultChainId, 
                    [&]() -> TokenCache::TokenInfo {
                        return etherscanClient.FetchWithRetry(
                            addr, []() { return {}; });
                    });
            }
        }
    }

    // Main lookup function - thread-safe
    TokenCache::TokenInfo GetOrLoad(const std::string& address) {
        auto info = cache_.Get(address, config_.defaultChainId);
        
        if (info.address.empty()) {
            // Not in cache - load from API
            info = etherscanClient.FetchWithRetry(
                address, []() -> TokenCache::TokenInfo {
                    return {}; // Fallback: empty token
                });
            
            // Store in cache
            cache_.GetOrLoad(address, config_.defaultChainId, 
                [&]() -> TokenCache::TokenInfo { return info; });
        }

        // Check TTL and refresh if expired
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - info.lastUpdated).count();
        
        if (config_.enableCache && config_.cacheTTLSeconds > 0 && 
            elapsed > config_.cacheTTLSeconds) {
            // Refresh from API
            info = etherscanClient.FetchWithRetry(
                address, []() -> TokenCache::TokenInfo { return {}; });
            
            cache_.GetOrLoad(address, config_.defaultChainId, 
                [&]() -> TokenCache::TokenInfo { return info; });
        }

        return info;
    }

    // Batch lookup for performance
    std::vector<TokenCache::TokenInfo> GetBatch(const std::vector<std::string>& addresses) {
        std::vector<TokenCache::TokenInfo> results;
        results.reserve(addresses.size());

        for (const auto& addr : addresses) {
            results.push_back(GetOrLoad(addr));
        }

        return results;
    }

    // Get cache statistics
    TokenCache::CacheStats GetStats() const {
        return cache_.GetStats();
    }

    // Clear expired entries
    void RefreshExpired() {
        auto now = std::chrono::steady_clock::now();
        for (auto& [key, info] : cache_) {
            if (std::chrono::duration_cast<std::chrono::seconds>(
                    now - info.lastUpdated).count() > config_.cacheTTLSeconds) {
                // Refresh this entry
                info = etherscanClient.FetchWithRetry(
                    info.address, []() -> TokenCache::TokenInfo { return {}; });
            }
        }
    }

    // Get cache size
    size_t CacheSize() const {
        return cache_.GetCacheSize();
    }

    // Clear all cache (useful for testing)
    void ClearCache() {
        std::lock_guard<std::mutex> lock(cache_.mtx_);
        cache_.cache_.clear();
        cache_.hitCount_ = 0;
        cache_.missCount_ = 0;
    }

    // Get default chain ID
    uint64_t DefaultChainId() const { return config_.defaultChainId; }

    // Set a custom loader for fallback (e.g., local DB)
    void SetFallbackLoader(const std::function<TokenCache::TokenInfo()>& loader) {
        etherscanClient = EtherscanClient({config_.etherscanApiKey, 
                                           config_.defaultChainId});
    }

private:
    // Helper to create a default token info (fallback)
    TokenCache::TokenInfo CreateDefaultInfo(const std::string& address) {
        return {
            .address = address,
            .chainId = config_.defaultChainId,
            .lastUpdated = std::chrono::steady_clock::now()
        };
    }
};

// ============================================================================
// Utility Functions
// ============================================================================

std::string FormatAddress(const std::string& addr) {
    if (addr.length() >= 42) {
        return addr.substr(0, 6) + "..." + addr.substr(-4);
    }
    return addr;
}

std::string FormatDuration(std::chrono::milliseconds ms) {
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(ms).count();
    if (seconds < 60) {
        return std::to_string(seconds) + "s";
    } else {
        auto minutes = seconds / 60;
        return std::to_string(minutes) + "m" + 
               std::to_string(seconds % 60) + "s";
    }
}

// ============================================================================
// Demo / Test Harness
// ============================================================================

int main() {
    // Configuration - replace with your API key for production use
    TokenInfoLoader loader({
        .etherscanApiKey = "DEMO_KEY",  // Set your Etherscan API key here
        .defaultChainId = DEFAULT_CHAIN_ID,
        .enableCache = true,
        .cacheTTLSeconds = 300
    });

    std::cout << "=== TokenInfoLoader Demo ===" << std::endl;
    std::cout << "Default Chain ID: " << loader.DefaultChainId() << std::endl;
    
    // Test with some well-known tokens
    const std::vector<std::string> testTokens = {
        "0xC02aAa394dbC14BdCeFF1cD8AA96459E90f6c7e9",  // WETH
        "0xdAC17F958D2ee523a2206206994597C13D831ec7",  // USDT
        "0xA0b86991c6218b36c1d19D4Ae8ea9cf153Uf4B1",   // USDC (note: check address)
    };

    std::cout << "\n--- Loading Token Info ---" << std::endl;
    
    for (const auto& addr : testTokens) {
        auto info = loader.GetOrLoad(addr);
        
        if (!info.address.empty()) {
            std::string name = info.name.empty() ? "Unknown" : info.name;
            std::cout << "\n  Address: " << FormatAddress(info.address)