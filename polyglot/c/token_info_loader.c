/*
 * polyglot/c/token_info_loader.c
 * 
 * Token Info Loader for ApproveWarden
 * 
 * Loads token metadata, parses approval events, calculates drainer risk scores,
 * and generates revoke transactions. Self-contained implementation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>

/* ============================================================================
   Constants & Types
   ============================================================================ */

#define MAX_TOKENS 1024
#define MAX_APPROVALS 8192
#define CACHE_DIR "/tmp/approvewarden"
#define DEFAULT_CHAIN_ID 1ULL /* Ethereum mainnet */

/* ERC-20/721/1155 standard amounts */
#define UINT256_MAX ((uint64_t)~(uint64_t)0 << (sizeof(uint64_t) * 8 - 32))
#define INFINITE_ALLOWANCE UINT256_MAX

/* Risk thresholds */
#define HIGH_RISK_THRESHOLD 0.75
#define CRITICAL_APPROVAL_COUNT 10

/* ============================================================================
   Data Structures
   ============================================================================ */

typedef struct {
    uint256_t contract_address;
    char name[256];
    char symbol[32];
    uint8 decimals;
    uint64_t chain_id;
} TokenInfo;

typedef struct {
    uint256_t token_contract;
    uint256_t spender_address;
    uint256_t allowance_value;
    uint8 is_infinite;
    uint64_t last_updated;
} ApprovalRecord;

typedef struct {
    uint256_t wallet_address;
    uint64_t chain_id;
    uint32_t total_approvals;
    double drainer_risk_score;
    int critical_count;
} WalletState;

/* ============================================================================
   Global State
   ============================================================================ */

static TokenInfo token_cache[MAX_TOKENS];
static ApprovalRecord approval_records[MAX_APPROVALS];
static WalletState wallet_state;

/* ============================================================================
   Utility Functions
   ============================================================================ */

static inline uint256_t create_address(uint8_t *bytes) {
    if (!bytes) return 0;
    
    /* Simple hex to address conversion for demo */
    char hex[71];
    snprintf(hex, sizeof(hex), "%040x", (unsigned long)(uintptr_t)bytes);
    return (uint256_t)strtoull(hex, NULL, 16);
}

static inline uint8_t *get_bytes(uint256_t addr) {
    char hex[71];
    snprintf(hex, sizeof(hex), "%040x", (unsigned long)(uintptr_t)addr);
    
    /* Convert hex string to bytes */
    uint8_t *bytes = malloc(32);
    if (!bytes) return NULL;
    
    for (int i = 0; i < 32; i++) {
        sscanf(hex + i * 2, "%2hhx", &bytes[i]);
    }
    return bytes;
}

static inline uint64_t current_timestamp(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)(ts.tv_sec + ts.tv_nsec / 1000000000ULL);
}

/* ============================================================================
   Token Info Loader - Core Functions
   ============================================================================ */

int token_info_loader_init(void) {
    /* Initialize cache with common tokens */
    
    /* USDT (Tether) */
    uint8_t usdt_addr[32] = {0x06, 0xf1, 0xd7, 0xe5, 0x4b, 0x0d, 0x9a, 0x3e,
                             0xc6, 0x8c, 0x2f, 0x7c, 0x1c, 0x7d, 0x5e, 0x4b,
                             0x0d, 0x9a, 0x3e, 0xc6, 0x8c, 0x2f, 0x7c, 0x1c};
    TokenInfo *usdt = &token_cache[0];
    usdt->contract_address = create_address(usdt_addr);
    strncpy(usdt->name, "Tether USD", 256);
    strncpy(usdt->symbol, "USDT", 32);
    usdt->decimals = 6;
    usdt->chain_id = DEFAULT_CHAIN_ID;

    /* USDC (Circle) */
    uint8_t usdc_addr[32] = {0xa0, 0x24, 0xd3, 0xc4, 0x1c, 0x7a, 0x9e, 0xe6,
                             0x5f, 0x8b, 0x2d, 0x1e, 0x9f, 0x3c, 0x4b, 0x0d};
    TokenInfo *usdc = &token_cache[1];
    usdc->contract_address = create_address(usdc_addr);
    strncpy(usdc->name, "USD Coin", 256);
    strncpy(usdc->symbol, "USDC", 32);
    usdc->decimals = 6;
    usdc->chain_id = DEFAULT_CHAIN_ID;

    /* DAI */
    uint8_t dai_addr[32] = {0x1f, 0x9d, 0x4e, 0x7a, 0x5c, 0xb8, 0x2e, 0x9f,
                            0x6b, 0xc4, 0x3d, 0x1e, 0x8f, 0x2a, 0x7c, 0x5b};
    TokenInfo *dai = &token_cache[2];
    dai->contract_address = create_address(dai_addr);
    strncpy(dai->name, "Dai Stablecoin", 256);
    strncpy(dai->symbol, "DAI", 32);
    dai->decimals = 18;
    dai->chain_id = DEFAULT_CHAIN_ID;

    /* WETH */
    uint8_t weth_addr[32] = {0xc0, 0x2a, 0x3e, 0x5c, 0x6d, 0xb4, 0x1f, 0x9e,
                             0x7b, 0xc8, 0x2d, 0x3e, 0x1a, 0x8f, 0x5c, 0x4b};
    TokenInfo *weth = &token_cache[3];
    weth->contract_address = create_address(weth_addr);
    strncpy(weth->name, "Wrapped Ether", 256);
    strncpy(weth->symbol, "WETH", 32);
    weth->decimals = 18;
    weth->chain_id = DEFAULT_CHAIN_ID;

    /* ETH (native) */
    uint8_t eth_addr[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    TokenInfo *eth = &token_cache[4];
    eth->contract_address = create_address(eth_addr);
    strncpy(eth->name, "Ethereum", 256);
    strncpy(eth->symbol, "ETH", 32);
    eth->decimals = 18;
    eth->chain_id = DEFAULT_CHAIN_ID;

    return 0;
}

int token_info_load_from_cache(uint256_t addr) {
    for (int i = 0; i < MAX_TOKENS; i++) {
        if (token_cache[i].contract_address == addr) {
            return i; /* Found in cache */
        }
    }
    
    /* Not found - would fetch from remote API in production */
    wallet_state.drainer_risk_score = 0.1; /* Unknown token, low default risk */
    return -1;
}

int token_info_fetch_remote(uint256_t addr) {
    /* Simulated remote fetch - returns cached or new entry */
    
    for (int i = 0; i < MAX_TOKENS; i++) {
        if (token_cache[i].contract_address == addr) {
            return i;
        }
    }
    
    /* Add to cache if not exists and space available */
    if (MAX_TOKENS > 5) {
        TokenInfo *new_token = &token_cache[MAX_TOKENS - 1];
        
        /* Default unknown token info */
        new_token->contract_address = addr;
        strncpy(new_token->name, "Unknown ERC-20", 256);
        strncpy(new_token->symbol, "UNK", 32);
        new_token->decimals = 18;
        new_token->chain_id = DEFAULT_CHAIN_ID;
        
        return MAX_TOKENS - 1;
    }
    
    return -1;
}

/* ============================================================================
   Approval Parser Functions
   ============================================================================ */

int approval_parser_parse_event(uint256_t wallet_addr, 
                                uint256_t token_contract,
                                uint256_t spender,
                                uint256_t amount) {
    /* Check if we already have this approval record */
    for (int i = 0; i < MAX_APPROVALS; i++) {
        if (approval_records[i].token_contract == token_contract &&
            approval_records[i].spender_address == spender) {
            
            /* Update existing record */
            approval_records[i].allowance_value = amount;
            approval_records[i].is_infinite = (amount >= INFINITE_ALLOWANCE);
            approval_records[i].last_updated = current_timestamp();
            return 0;
        }
    }
    
    /* Add new record if space available */
    for (int i = 0; i < MAX_APPROVALS; i++) {
        if (approval_records[i].token_contract == 0) {
            approval_records[i].token_contract = token_contract;
            approval_records[i].spender_address = spender;
            approval_records[i].allowance_value = amount;
            approval_records[i].is_infinite = (amount >= INFINITE_ALLOWANCE);
            approval_records[i].last_updated = current_timestamp();
            
            /* Update wallet state */
            if (wallet_state.wallet_address == 0) {
                wallet_state.wallet_address = wallet_addr;
            }
            wallet_state.total_approvals++;
            
            return i;
        }
    }
    
    return -1;
}

int approval_parser_parse_event_infinite(uint256_t wallet_addr,
                                         uint256_t token_contract,
                                         uint256_t spender) {
    /* Direct infinite approval parser */
    for (int i = 0; i < MAX_APPROVALS; i++) {
        if (approval_records[i].token_contract == token_contract &&
            approval_records[i].spender_address == spender) {
            
            approval_records[i].allowance_value = INFINITE_ALLOWANCE;
            approval_records[i].is_infinite = 1;
            approval_records[i].last_updated = current_timestamp();
            return 0;
        }
    }
    
    for (int i = 0; i < MAX_APPROVALS; i++) {
        if (approval_records[i].token_contract == 0) {
            approval_records[i].token_contract = token_contract;
            approval_records[i].spender_address = spender;
            approval_records[i].allowance_value = INFINITE_ALLOWANCE;
            approval_records[i].is_infinite = 1;
            approval_records[i].last_updated = current_timestamp();
            
            if (wallet_state.wallet_address == 0) {
                wallet_state.wallet_address = wallet_addr;
            }
            wallet_state.total_approvals++;
            
            return i;
        }
    }
    
    return -1;
}

/* ============================================================================
   Risk Calculator Functions
   ============================================================================ */

double wallet_risk_calculator_calc_score(uint256_t wallet_addr) {
    if (wallet_state.wallet_address == 0 || 
       wallet_state.total_approvals == 0) {
        return 0.1; /* Default low risk for empty state */
    }
    
    double score = 0.0;
    int infinite_count = 0;
    int high_value_count = 0;
    int critical_tokens = 0;
    
    /* Count infinite approvals (highest risk) */
    for (int i = 0; i < MAX_APPROVALS; i++) {
        if (approval_records[i].is_infinite) {
            infinite_count++;
            
            /* Check if it's a critical token */
            for (int j = 0; j < MAX_TOKENS; j++) {
                if (token_cache[j].contract_address == approval_records[i].token_contract) {
                    if (strcmp(token_cache[j].symbol, "ETH") == 0 ||
                        strcmp(token_cache[j].symbol, "WETH") == 0 ||
                        strcmp(token_cache[j].symbol, "USDT") == 0 ||
                        strcmp(token_cache[j].symbol, "USDC") == 0 ||
                        strcmp(token_cache[j].symbol, "DAI") == 0) {
                        critical_tokens++;
                    }
                }
            }
        }
    }
    
    /* Calculate weighted score */
    /* Infinite: 50 points each, Critical infinite: 100 points each */
    score = (double)infinite_count * 50.0;
    score += (double)critical_tokens * 100.0;
    
    /* Normalize to 0-1 range */
    double max_possible = MAX_APPROVALS * 50.0 + CRITICAL_APPROVAL_COUNT * 100.0;
    score /= max_possible;
    
    /* Apply decay based on time since last update (simulated) */
    uint64_t age = current_timestamp() - wallet_state.last_updated;
    if (age > 86400) { /* More than a day old */
        score *= 0.95;
    }
    
    return fmin(score, 1.0);
}

int wallet_risk_calculator_update_score(uint256_t wallet_addr) {
    wallet_state.drainer_risk_score = 
        wallet_risk_calculator_calc_score(wallet_addr);
    wallet_state.last_updated = current_timestamp();
    
    return (wallet_state.drainer_risk_score >= HIGH_RISK_THRESHOLD);
}

/* ============================================================================
   Revoke Transaction Generator Functions
   ============================================================================ */

typedef struct {
    uint256_t from;
    uint256_t to;
    uint256_t value;
    uint8 is_infinite;
    char token_symbol[32];
} RevokeTx;

static int revoke_tx_count = 0;
static RevokeTx revoke_transactions[MAX_APPROVALS];

int revoke_transaction_generator_create_tx(uint256_t wallet_addr, 
                                          uint256_t token_contract) {
    /* Find matching approval record */
    for (int i = 0; i