#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#define MAX_TOKENS 256
#define MAX_APPROVALS_PER_TOKEN 1024
#define MAX_WALLETS 64
#define BUFFER_SIZE 8192

/* ABI constants */
#define ERC20_TRANSFER_ALLOWANCE_SIGNATURE "TransferAllowance(address,uint256)"
#define ERC20_APPROVE_FOR_ALL_SIGNATURE "ApproveForAll(address,address,uint256)"
#define ERC721_OPERATOR_APPROVAL_SIGNATURE "OperatorApproval(address,address,uint256,bool)"

/* Severity thresholds */
#define SEVERITY_CRITICAL 9.0
#define SEVERITY_HIGH     7.0
#define SEVERITY_MEDIUM   4.0
#define SEVERITY_LOW      1.0

/* Transaction types for revocation */
typedef enum {
    TX_TYPE_TRANSFER_ALLOWANCE,
    TX_TYPE_APPROVE_FOR_ALL,
    TX_TYPE_OPERATOR_APPROVAL,
    TX_TYPE_REVOKE_ALL
} TxType;

/* Severity levels */
typedef enum {
    SEV_CRITICAL = 9,
    SEV_HIGH     = 7,
    SEV_MEDIUM   = 4,
    SEV_LOW      = 1
} SeverityLevel;

/* ABI-encoded event data structure */
typedef struct {
    uint8_t signature[32];           /* Event selector (first 4 bytes) */
    uint64_t param_count;            /* Number of parameters */
    uint8_t params[BUFFER_SIZE];     /* Raw parameter data */
} AbiEvent;

/* ERC-20 TransferAllowance event */
typedef struct {
    char token_address[65];          /* Full Ethereum address (hex) */
    uint64_t amount;                 /* Amount approved */
    SeverityLevel severity;
    double score;                    /* Drainer exposure score */
} TransferAllowance;

/* ERC-20 ApproveForAll event */
typedef struct {
    char token_address[65];
    char spender_address[65];
    uint64_t allowance;
    SeverityLevel severity;
    double score;
} ApproveForAll;

/* ERC-721/1155 OperatorApproval event */
typedef struct {
    char operator_address[65];
    char token_contract[65];
    uint64_t amount_or_all;          /* 0xFFFFFFFFFFFFFFFF = all */
    bool is_approved;               /* true if approved (dangerous) */
    SeverityLevel severity;
    double score;
} OperatorApproval;

/* Wallet status summary */
typedef struct {
    char wallet_address[65];
    uint32_t total_approvals;
    double max_score;
    SeverityLevel max_severity;
    time_t last_updated;
} WalletStatus;

/* Main approval record for a token */
typedef struct {
    char contract_address[65];
    uint32_t approval_count;
    TransferAllowance transfer_allowances[MAX_APPROVALS_PER_TOKEN];
    ApproveForAll approve_for_all;
    OperatorApproval operator_approvals[MAX_APPROVALS_PER_TOKEN];
} TokenRecord;

/* Global state */
static WalletStatus wallet_statuses[MAX_WALLETS];
static uint32_t wallet_count = 0;
static TokenRecord token_records[MAX_TOKENS];
static uint32_t token_record_count = 0;

/* Forward declarations */
static void parse_abi_event(const uint8_t* data, AbiEvent* event);
static SeverityLevel calculate_severity(uint64_t amount, const char* spender, bool is_all);
static double calculate_exposure_score(TransferAllowance* ta, ApproveForAll* afall, OperatorApproval* oa);
static void generate_revoke_tx(const TokenRecord* token, uint32_t index, TxType type, FILE* out);
static void update_wallet_status(char* wallet_addr, uint64_t score, SeverityLevel sev);

/* ============ ABI PARSING ============ */

static inline bool is_valid_address(const char* addr) {
    return strlen(addr) == 64 && (addr[0] == '0' || addr[0] == '1');
}

static inline uint32_t hex_to_dec(const char* str, size_t len) {
    if (!str || !len) return 0;
    
    const char* end = str + len;
    unsigned long result = 0;
    
    while (str < end && *str != '\0') {
        if (*str >= '0' && *str <= '9') {
            result = result * 16 + (*str - '0');
        } else if (*str >= 'a' && *str <= 'f') {
            result = result * 16 + (tolower(*str) - 'a' + 10);
        } else if (*str >= 'A' && *str <= 'F') {
            result = result * 16 + (*str - 'A' + 10);
        } else {
            break;
        }
        str++;
    }
    
    return (uint32_t)result;
}

static inline uint8_t* abi_event_selector(const char* signature, uint8_t* out) {
    if (!signature || !out) return NULL;
    
    /* Extract first 4 bytes of the signature as event selector */
    memcpy(out, signature, 4);
    return out + 4;
}

static SeverityLevel calculate_severity(uint64_t amount, const char* spender, bool is_all) {
    if (is_all || !spender) {
        /* Approve for all = critical */
        return SEV_CRITICAL;
    }
    
    uint32_t addr_len = strlen(spender);
    if (addr_len < 64) {
        /* Short address, likely a known drainer or contract */
        if (amount > 1000000000000000000ULL) {
            return SEV_CRITICAL;
        } else if (amount > 100000000000000000ULL) {
            return SEV_HIGH;
        } else {
            return SEV_MEDIUM;
        }
    }
    
    /* Normal approval - check amount */
    if (amount > 1000000000000000000ULL) {
        return SEV_CRITICAL;
    } else if (amount > 100000000000000000ULL) {
        return SEV_HIGH;
    } else if (amount > 10000000000000000ULL) {
        return SEV_MEDIUM;
    }
    
    return SEV_LOW;
}

static double calculate_exposure_score(TransferAllowance* ta, ApproveForAll* afall, OperatorApproval* oa) {
    if (!ta && !afall && !oa) return 0.0;
    
    double score = 0.0;
    
    /* Transfer Allowance contribution */
    if (ta) {
        /* Base score from amount relative to critical threshold */
        uint64_t critical_threshold = 1000000000000000000ULL;
        double amount_ratio = ta->amount / (double)critical_threshold;
        
        if (ta->severity == SEV_CRITICAL) {
            score += 5.0 * amount_ratio;
        } else if (ta->severity == SEV_HIGH) {
            score += 3.0 * amount_ratio;
        } else if (ta->severity == SEV_MEDIUM) {
            score += 1.5 * amount_ratio;
        } else {
            score += 0.5 * amount_ratio;
        }
    }
    
    /* ApproveForAll contribution */
    if (afall) {
        double afall_ratio = afall->allowance / (double)critical_threshold;
        score += 4.0 + (2.0 * afall_ratio);
        
        /* Check if spender is a known risky contract pattern */
        uint32_t len = strlen(afall->spender_address);
        if (len >= 60 && memcmp(afall->spender_address, "0x", 2) == 0) {
            /* Last byte check for common drainer patterns */
            unsigned char last_byte = afall->spender_address[63];
            if ((last_byte & 0xF) < 4 || (last_byte & 0xF) > 12) {
                score += 2.0;
            }
        }
    }
    
    /* Operator Approval contribution */
    if (oa) {
        if (oa->is_approved && oa->amount_or_all == 0xFFFFFFFFFFFFFFFFULL) {
            /* Approved for all tokens = very dangerous */
            score += 6.0;
        } else if (oa->is_approved) {
            /* Partial approval - still risky */
            double partial_ratio = oa->amount_or_all / (double)critical_threshold;
            score += 3.0 + (1.5 * partial_ratio);
        }
    }
    
    return fmin(score, 10.0);  /* Cap at 10.0 */
}

/* ============ WALLET STATUS UPDATES ============ */

static void update_wallet_status(char* wallet_addr, uint64_t score, SeverityLevel sev) {
    if (!wallet_addr || !strlen(wallet_addr)) return;
    
    /* Find existing wallet or create new one */
    for (uint32_t i = 0; i < wallet_count && wallet_statuses[i].total_approvals > 0; i++) {
        uint32_t len = strlen(wallet_statuses[i].wallet_address);
        if (len == 64 && memcmp(wallet_statuses[i].wallet_address, wallet_addr, 64) == 0) {
            /* Update existing */
            if (score > wallet_statuses[i].max_score) {
                wallet_statuses[i].max_score = score;
            }
            if ((uint32_t)sev > (uint32_t)wallet_statuses[i].max_severity) {
                wallet_statuses[i].max_severity = sev;
            }
            return;
        }
    }
    
    /* Create new wallet entry */
    if (wallet_count < MAX_WALLETS) {
        strncpy(wallet_statuses[wallet_count].wallet_address, wallet_addr, 64);
        wallet_statuses[wallet_count].total_approvals = 1;
        wallet_statuses[wallet_count].max_score = score;
        wallet_statuses[token_record_count].max_severity = sev;
        wallet_statuses[wallet_count].last_updated = time(NULL);
        wallet_count++;
    }
}

/* ============ REVOKE TRANSACTION GENERATION ============ */

static void generate_revoke_tx(const TokenRecord* token, uint32_t index, TxType type, FILE* out) {
    if (!token || !out) return;
    
    /* Build transaction data based on type */
    switch (type) {
        case TX_TYPE_TRANSFER_ALLOWANCE: {
            const TransferAllowance* ta = &token->transfer_allowances[index];
            if (!ta) break;
            
            fprintf(out, "TX: TransferAllowance Revoke\n");
            fprintf(out, "  Contract: %s\n", token->contract_address);
            fprintf(out, "  Amount: %.0f (%.2f ETH)\n", ta->amount, (double)ta->amount / 1e18);
            fprintf(out, "  Spender: %s\n", ta->severity == SEV_CRITICAL ? "CRITICAL" : 
                           ta->severity == SEV_HIGH ? "HIGH" : 
                           ta->severity == SEV_MEDIUM ? "MEDIUM" : "LOW");
            break;
        }
        
        case TX_TYPE_APPROVE_FOR_ALL: {
            const ApproveForAll* afall = &token->approve_for_all;
            if (!afall) break;
            
            fprintf(out, "TX: ApproveForAll Revoke\n");
            fprintf(out, "  Contract: %s\n", token->contract_address);
            fprintf(out, "  Spender: %s\n", afall->spender_address);
            fprintf(out, "  Allowance: %.0f (%.2f ETH)\n", afall->allowance, (double)afall->allowance / 1e18);
            break;
        }
        
        case TX_TYPE_OPERATOR_APPROVAL: {
            const OperatorApproval* oa = &token->operator_approvals[index];
            if (!oa) break;
            
            fprintf(out, "TX: OperatorApproval Revoke\n");
            fprintf(out, "  Contract: %s\n", token->contract_address);
            fprintf(out, "  Operator: %s\n", oa->operator_address);
            fprintf(out, "  Amount: %.0f (All if 0xFFFFFFFFFFFFFFFF)\n", oa->amount_or_all);
            fprintf(out, "  Status: %s\n", oa->is_approved ? "APPROVED" : "REVOKED");
            break;
        }
        
        case TX_TYPE_REVOKE_ALL: {
            fprintf(out, "TX: RevokeAll (Emergency)\n");
            fprintf(out, "  Contract: %s\n", token->contract_address);
            fprintf(out, "  Total Approvals: %u\n", token->approval_count);
            break;
        }
    }
}

/* ============ SCORING ENGINE ============ */

static double evaluate_token_risk(const TokenRecord* token) {
    if (!token || !token->approval_count) return 0.0;
    
    double max_score = 0.0;
    SeverityLevel max_sev = SEV_LOW;
    
    /* Check Transfer Allowances */
    for (uint32_t i = 0; i < token->approval_count && i < MAX_APPROVALS_PER_TOKEN; i++) {
        if (token->transfer_allowances[i].amount > 0) {
            double score = calculate_exposure_score(&token->transfer_allowances[i], 
                                                     &token->approve_for_all, 
                                                     NULL);
            max_score = fmax(max_score, score);
            
            SeverityLevel sev = token->transfer_allowances[i].severity;
            if ((uint32_t)sev > (uint32_t)max_sev) {
                max_sev = sev;
            }
        }
    }
    
    /* Check ApproveForAll */
    if (token->approve_for_all.allowance > 0) {
        double score = calculate_exposure_score(&token->transfer_allowances[0], 
                                                 &token->approve_for_all, 
                                                 NULL);
        max_score = fmax(max_score, score);
        
        SeverityLevel sev = SEV_CRITICAL;
        if ((uint32_t)sev > (uint32_t)max_sev) {
            max_sev = sev;
        }
    }
    
    /* Check Operator Approvals */
    for (uint32_t i = 0; i < token->approval_count && i < MAX_APPROVALS_PER_TOKEN; i++) {
        if (token->operator_approvals[i].is_approved) {
            double score = calculate_exposure_score(&token->transfer_allowances[0], 
                                                     &token->approve_for_all, 
                                                     &token->operator_approvals[i]);
            max_score = fmax(max_score, score);
            
            SeverityLevel sev = token->operator_approvals[i].severity;
            if ((uint32_t)sev > (uint32_t)max_sev) {
                max_sev = sev;
            }
        }
    }
    
    return max_score;
}

/* ============ MAIN ENTRY POINT ============ */

static void print_header(void) {
    printf("============================================================\n");
    printf("  APPROVEWARDEN: ERC-20/721/1155 Approval Query Engine\n");
    printf("  Version 1.0.0 - Production Ready\n");
    printf("============================================================\n\n");
}

static void print_summary(void) {
    printf("\n--- WALLET SUMMARY ---\n");
    
    for (uint32_t i = 0; i < wallet_count; i++) {
        SeverityLevel sev_str[5] = {"LOW", "MEDIUM", "HIGH", "CRITICAL"};
        
        char sev_display[16];
        if (wallet_statuses[i].max_severity == SEV_CRITICAL) {
            strcpy(sev_display, "[CRITICAL]");
        } else if (wallet_statuses[i].max_severity == SEV_HIGH) {
            strcpy(sev_display, "[HIGH]");
        } else if (wallet_statuses[i].max_severity == SEV_MEDIUM) {
            strcpy(sev_display, "[MEDIUM]");
        } else {
            strcpy(sev_display, "[LOW]");
        }
        
        printf("%s %s\n", sev_display, wallet_statuses[i].wallet_address);
        printf("  Score: %.2f | Approvals: %u\n", 
               wallet_statuses[i].max_score, 
               wallet_statuses[i].total