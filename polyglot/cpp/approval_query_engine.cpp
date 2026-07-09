#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cmath>

// ============================================================================
// Constants and Configuration
// ============================================================================

namespace config {
    constexpr uint64_t HIGH_VALUE_THRESHOLD_USD = 1000000;      // 1M USD
    constexpr uint256_t INFINITE_ALLOWANCE = std::numeric_limits<uint256_t>::max();
    constexpr double USDC_PRICE_USD = 1.00;                      // Approximate
    constexpr size_t MAX_LOGS_PER_BLOCK = 10000;
}

// ============================================================================
// Utility Types and Macros
// ============================================================================

using uint8_t = unsigned char;
using uint256_t = unsigned long long;  // Simplified for demo (real impl uses 32 bytes)

inline bool is_infinite(uint256_t value) {
    return value == config::INFINITE_ALLOWANCE || 
           value > config::HIGH_VALUE_THRESHOLD_USD * 1000000;
}

// ============================================================================
// ABI Encoding/Decoding Helpers
// ============================================================================

struct Address {
    uint8_t data[20];
    
    static const char* hex_prefix = "0x";
    
    std::string to_hex() const {
        std::ostringstream oss;
        oss << config::hex_prefix;
        for (int i = 19; i >= 0; --i) {
            oss << std::hex << std::setfill('0') 
                << std::setw(2) << static_cast<int>(data[i]);
        }
        return oss.str();
    }
    
    bool operator==(const Address& other) const {
        return memcmp(data, other.data, 20) == 0;
    }
};

struct Bytes32 {
    uint8_t data[32];
    
    std::string to_hex() const {
        std::ostringstream oss;
        for (int i = 31; i >= 0; --i) {
            oss << std::hex << std::setfill('0') 
                << std::setw(2) << static_cast<int>(data[i]);
        }
        return oss.str();
    }
};

// ============================================================================
// Token Types and Metadata
// ============================================================================

enum class TokenType { ERC_20, ERC_721, ERC_1155 };

struct TokenInfo {
    Address address;
    std::string name;
    std::string symbol;
    uint8_t decimals = 6;
    TokenType type = TokenType::ERC_20;
    
    double usd_value(uint256_t balance) const {
        if (decimals == 18 && type == TokenType::ERC_20) {
            // Assume WETH/USDC-like token, estimate at $1M per 1e18 for demo
            return static_cast<double>(balance / 1e18);
        }
        return 0.0;
    }
};

// ============================================================================
// Approval Event Structure
// ============================================================================

struct ApprovalEvent {
    Address owner;
    Address spender;
    uint256_t amount;
    TokenInfo token;
    TokenType type;
    bool is_infinite = false;
    
    double estimated_usd_value() const {
        if (is_infinite) return config::HIGH_VALUE_THRESHOLD_USD * 100.0;
        return token.usd_value(amount);
    }
};

// ============================================================================
// Scoring Engine - Calculates Drainer Exposure Risk
// ============================================================================

struct ScoringResult {
    uint8_t risk_level = 0;           // 0-10 scale
    double exposure_score = 0.0;      // 0.0 to 1.0
    std::vector<ApprovalEvent> critical_approvals;
    
    static const char* risk_label(uint8_t level) {
        switch(level) {
            case 0: return "LOW";
            case 1: return "MODERATE";
            case 2: return "HIGH";
            default: return "CRITICAL";
        }
    }
};

class ScoringEngine {
public:
    std::map<Address, uint64_t> spender_frequency;
    
    void add_approvals(const std::vector<ApprovalEvent>& events) {
        for (const auto& ev : events) {
            if (!ev.is_infinite && ev.estimated_usd_value() < 1000) continue;
            
            spender_frequency[ev.spender]++;
            if (ev.is_infinite || ev.estimated_usd_value() > config::HIGH_VALUE_THRESHOLD_USD) {
                ev.risk_level = 3;
                critical_approvals.push_back(ev);
            }
        }
    }
    
    ScoringResult calculate(const std::vector<ApprovalEvent>& events) const {
        ScoringResult result;
        
        double total_exposure = 0.0;
        uint64_t infinite_count = 0;
        uint64_t high_value_count = 0;
        
        for (const auto& ev : events) {
            if (ev.is_infinite) {
                infinite_count++;
                total_exposure += config::HIGH_VALUE_THRESHOLD_USD * 100.0;
            } else if (ev.estimated_usd_value() > config::HIGH_VALUE_THRESHOLD_USD) {
                high_value_count++;
                total_exposure += ev.estimated_usd_value();
            }
        }
        
        // Calculate exposure score (0-1)
        double max_expected = config::HIGH_VALUE_THRESHOLD_USD * 500.0;
        result.exposure_score = std::min(1.0, total_exposure / max_expected);
        
        // Risk level calculation
        uint8_t risk = 0;
        if (infinite_count > 0) risk += 2;
        if (high_value_count > 5) risk += 2;
        if (result.exposure_score > 0.7) risk += 1;
        
        result.risk_level = std::min(10, risk);
        result.critical_approvals = critical_approvals;
        
        return result;
    }
};

// ============================================================================
// Transaction Builder for Revocations
// ============================================================================

struct RevokeTx {
    Address from;
    Address to;  // spender to revoke against
    uint256_t amount = config::INFINITE_ALLOWANCE;
    
    std::string to_hex() const {
        std::ostringstream oss;
        oss << "0x" << from.to_hex();
        oss << " -> " << to.to_hex();
        if (amount != config::INFINITE_ALLOWANCE) {
            oss << " (" << amount << ")";
        }
        return oss.str();
    }
};

class TxBuilder {
public:
    std::vector<RevokeTx> build_revocations(const ScoringResult& result, 
                                            const Address& wallet) {
        std::vector<RevokeTx> txs;
        
        for (const auto& ev : result.critical_approvals) {
            RevokeTx tx;
            tx.from = wallet;
            tx.to = ev.spender;
            
            if (!ev.is_infinite && ev.estimated_usd_value() < config::HIGH_VALUE_THRESHOLD_USD * 10) {
                // Only revoke high-value or infinite, not small amounts
                continue;
            }
            
            txs.push_back(tx);
        }
        
        return txs;
    }
};

// ============================================================================
// Main Query Engine Class
// ============================================================================

class ApprovalQueryEngine {
private:
    ScoringEngine scorer;
    TxBuilder revoker;
    
public:
    struct QueryResult {
        std::vector<ApprovalEvent> all_approvals;
        ScoringResult score;
        std::vector<RevokeTx> revocation_txs;
        Address wallet;
        
        bool is_dangerous() const {
            return score.risk_level >= 2 || !score.critical_approvals.empty();
        }
    };
    
    QueryResult query(const Address& wallet, 
                     const std::vector<ApprovalEvent>& events) {
        QueryResult result;
        result.wallet = wallet;
        
        // Parse and normalize events
        for (const auto& ev : events) {
            if (!result.all_approvals.empty() && 
                result.all_approvals.back().owner != wallet) {
                break;  // Different owner, stop parsing this block
            }
            
            result.all_approvals.push_back(ev);
        }
        
        // Calculate score
        result.score = scorer.calculate(result.all_approvals);
        
        // Build revocation transactions
        result.revocation_txs = revoker.build_revocations(result.score, wallet);
        
        return result;
    }
    
    void print_result(const QueryResult& result) const {
        std::cout << "\n=== Wallet: " << result.wallet.to_hex() << " ===\n";
        std::cout << "Total Approvals Found: " << result.all_approvals.size() << "\n";
        std::cout << "Risk Level: " << ScoringEngine::risk_label(result.score.risk_level) 
                  << " (" << static_cast<int>(result.score.risk_level) << "/10)\n";
        std::cout << "Exposure Score: " << std::fixed << std::setprecision(2) 
                  << (result.score.exposure_score * 100.0) << "%\n\n";
        
        if (!result.all_approvals.empty()) {
            std::cout << "--- Top Critical Approvals ---\n";
            for (const auto& ev : result.score.critical_approvals) {
                double value = ev.is_infinite ? "INFINITE" 
                    : std::fixed << std::setprecision(2) << ev.estimated_usd_value() << " USD";
                
                std::cout << "  Token: " << ev.token.symbol << " (" << ev.token.address.to_hex() << ")\n";
                std::cout << "    Owner:   " << ev.owner.to_hex() << "\n";
                std::cout << "    Spender: " << ev.spender.to_hex() << "\n";
                std::cout << "    Amount:  " << value << "\n\n";
            }
        }
        
        if (!result.revocation_txs.empty()) {
            std::cout << "--- Suggested Revocations ---\n";
            for (const auto& tx : result.revocation_txs) {
                std::cout << "  " << tx.to_hex() << "\n";
            }
        } else if (!result.all_approvals.empty()) {
            std::cout << "--- No Immediate Revocations Needed ---\n";
        }
        
        std::cout << "\n";
    }
};

// ============================================================================
// Demo / Main Entry Point
// ============================================================================

int main() {
    ApprovalQueryEngine engine;
    
    // Sample test data - simulating parsed events from a wallet
    Address test_wallet;
    for (int i = 0; i < 20; ++i) test_wallet.data[i] = static_cast<uint8_t>(i);
    
    std::vector<ApprovalEvent> sample_events;
    
    // Critical: Infinite approval to known drainer pattern
    ApprovalEvent critical1;
    critical1.owner = test_wallet;
    critical1.spender.address[0] = 0x42;  // Known drainer prefix
    for (int i = 1; i < 20; ++i) critical1.spender.data[i] = static_cast<uint8_t>(i);
    critical1.amount = config::INFINITE_ALLOWANCE;
    critical1.token.address[0] = 0x6B;   // USDC-like token
    for (int i = 1; i < 21; ++i) critical1.token.address[i] = static_cast<uint8_t>(i);
    critical1.token.symbol = "USDC";
    critical1.token.decimals = 6;
    critical1.is_infinite = true;
    
    // High value but finite
    ApprovalEvent high_value;
    high_value.owner = test_wallet;
    for (int i = 0; i < 20; ++i) high_value.spender.data[i] = static_cast<uint8_t>(i + 5);
    high_value.amount = config::HIGH_VALUE_THRESHOLD_USD * 1000;  // 1B USDC
    high_value.token.address[0] = 0x6B;
    for (int i = 1; i < 21; ++i) high_value.token.address[i] = static_cast<uint8_t>(i);
    high_value.token.symbol = "USDC";
    high_value.token.decimals = 6;
    
    // Moderate - still worth watching
    ApprovalEvent moderate;
    moderate.owner = test_wallet;
    for (int i = 0; i < 20; ++i) moderate.spender.data[i] = static_cast<uint8_t>(i + 10);
    moderate.amount = config::HIGH_VALUE_THRESHOLD_USD * 50;   // 500K USDC
    moderate.token.address[0] = 0x6B;
    for (int i = 1; i < 21; ++i) moderate.token.address[i] = static_cast<uint8_t>(i);
    moderate.token.symbol = "USDC";
    moderate.token.decimals = 6;
    
    // Low value - probably safe to ignore
    ApprovalEvent low_value;
    low_value.owner = test_wallet;
    for (int i = 0; i < 20; ++i) low_value.spender.data[i] = static_cast<uint8_t>(i + 15);
    low_value.amount = config::HIGH_VALUE_THRESHOLD_USD * 2;   // 2K USDC
    low_value.token.address[0] = 0x6B;
    for (int i = 1; i < 21; ++i) low_value.token.address[i] = static_cast<uint8_t>(i);
    low_value.token.symbol = "USDC";
    low_value.token.decimals = 6;
    
    // Run query
    QueryResult result = engine.query(test_wallet, sample_events);
    
    // Output results
    print_result(result);
    
    if (result.is_dangerous()) {
        std::cout << "⚠️  WARNING: Wallet shows dangerous approval patterns!\n";
        std::cout << "   Consider executing suggested revocations immediately.\n\n";
    } else {
        std::cout << "✓ Wallet appears relatively safe.\n";
    }
    
    return 0;
}