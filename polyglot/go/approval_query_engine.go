package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

// =============================================================================
// TYPES & CONSTANTS
// =============================================================================

const (
	DefaultGasLimit     = 210000
	DefaultGasPriceGwei = 30
	MaxConcurrentQueries = 50
)

var (
	ErrNoWalletFound    = fmt.Errorf("no wallet found")
	ErrInvalidAddress   = fmt.Errorf("invalid address")
	ErrNetworkMismatch  = fmt.Errorf("network mismatch")
)

// TokenType represents the EIP standard of a token.
type TokenType int

const (
	TokenERC20 TokenType = iota
	TokenERC721
	TokenERC1155
)

// ApprovalStatus describes the state of an approval.
type ApprovalStatus string

const (
	StatusApproved    ApprovalStatus = "approved"
	StatusUnlimited   ApprovalStatus = "unlimited"
	StatusPending     ApprovalStatus = "pending"
	StatusRevoked     ApprovalStatus = "revoked"
)

// DrainerRiskLevel indicates how dangerous an approval is.
type DrainerRiskLevel int

const (
	RiskLow DrainerRiskLevel = iota
	RiskMedium
	RiskHigh
	RiskCritical
)

// TokenApproval represents a single ERC-20/721/1155 approval.
type TokenApproval struct {
	TokenAddress    common.Address `json:"token_address"`
	Owner           common.Address `json:"owner"`
	Approver        common.Address `json:"approver"`
	Operator         *common.Address `json:"operator,omitempty"` // For 721/1155 operator approvals
	Allowance        *big.Int       `json:"allowance"`          // For ERC-20
	TokenID          *big.Int       `json:"token_id,omitempty"` // For 721/1155
	Type             TokenType      `json:"type"`
	Status           ApprovalStatus  `json:"status"`
	IsUnlimited      bool            `json:"is_unlimited"`
	BlockNumber      uint64          `json:"block_number"`
	Timestamp        time.Time       `json:"timestamp"`
}

// WalletScanResult holds the aggregated results for a wallet.
type WalletScanResult struct {
	WalletAddress    common.Address  `json:"wallet_address"`
	TotalApprovals   int             `json:"total_approvals"`
	CriticalCount    int             `json:"critical_count"`
	HighRiskCount    int             `json:"high_risk_count"`
	MediumRiskCount  int             `json:"medium_risk_count"`
	TotalValueUSD    *big.Float      `json:"total_value_usd,omitempty"`
	DrainerExposure  float64         `json:"drainer_exposure"`
	RevokeTxns       []types.TxData  `json:"revoke_transactions"`
	ScanTime         time.Duration   `json:"scan_time_ms"`
}

// QueryConfig holds configuration for the approval query engine.
type QueryConfig struct {
	GasLimit     uint64
	GasPriceGwei float64
	MaxRetries   int
	Timeout      time.Duration
}

// =============================================================================
// QUERY ENGINE INTERFACE & IMPLEMENTATION
// =============================================================================

// ApprovalQueryEngine handles all ERC-20/721/1155 approval queries.
type ApprovalQueryEngine struct {
	client     *ethclient.Client
	config     QueryConfig
	mu         sync.RWMutex
	knownTokens map[common.Address]TokenType
}

// NewApprovalQueryEngine creates a new engine instance.
func NewApprovalQueryEngine(client *ethclient.Client, cfg ...*QueryConfig) (*ApprovalQueryEngine, error) {
	var config QueryConfig
	if len(cfg) > 0 && cfg[0] != nil {
		config = *cfg[0]
	} else {
		config.GasLimit = DefaultGasLimit
		config.GasPriceGwei = DefaultGasPriceGwei
		config.MaxRetries = 3
		config.Timeout = 10 * time.Second
	}

	engine := &ApprovalQueryEngine{
		client:      client,
		config:      config,
		knownTokens: make(map[common.Address]TokenType),
	}

	// Pre-populate known tokens from common contracts
	if err := engine.loadKnownTokens(); err != nil {
		return nil, fmt.Errorf("failed to load known tokens: %w", err)
	}

	return engine, nil
}

// LoadKnownTokens populates the cache with well-known token contracts.
func (e *ApprovalQueryEngine) loadKnownTokens() error {
	known := map[common.Address]TokenType{
		common.HexToAddress("0xC02aA..."): TokenERC20, // USDC
		common.HexToAddress("0xA0b869915..."): TokenERC20, // USDT
		common.HexToAddress("0xdAC17f958..."): TokenERC20, // USDT (old)
	}

	for addr := range known {
		e.knownTokens[addr] = TokenERC20
	}

	return nil
}

// QueryWalletApprovals returns all active approvals for a given wallet.
func (e *ApprovalQueryEngine) QueryWalletApprovals(ctx context.Context, wallet common.Address, tokenTypes ...TokenType) ([]*TokenApproval, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var results []*TokenApproval

	// ERC-20 approvals: query all non-zero allowances
	if slices.Contains(tokenTypes, TokenERC20) {
		erc20Approvals, err := e.queryERC20Approvals(ctx, wallet)
		if err != nil {
			return nil, fmt.Errorf("querying ERC-20: %w", err)
		}
		results = append(results, erc20Approvals...)
	}

	// ERC-721 approvals: query operator approvals
	if slices.Contains(tokenTypes, TokenERC721) {
		erc721Approvals, err := e.queryERC721OperatorApprovals(ctx, wallet)
		if err != nil {
			return nil, fmt.Errorf("querying ERC-721: %w", err)
		}
		results = append(results, erc721Approvals...)
	}

	// ERC-1155 approvals: query operator approvals
	if slices.Contains(tokenTypes, TokenERC1155) {
		erc1155Approvals, err := e.queryERC1155OperatorApprovals(ctx, wallet)
		if err != nil {
			return nil, fmt.Errorf("querying ERC-1155: %w", err)
		}
		results = append(results, erc1155Approvals...)
	}

	return results, nil
}

// queryERC20Approvals fetches all non-zero allowances for a wallet.
func (e *ApprovalQueryEngine) queryERC20Approvals(ctx context.Context, wallet common.Address) ([]*TokenApproval, error) {
	var approvals []*TokenApproval

	// Get the user's allowance mapping from their storage slot
	// Slot 0: owner -> spender -> amount
	ownerSlot := types.StorageSlot(wallet.Bytes())

	// Query a set of known ERC-20 tokens for efficiency
	knownERC20s := []common.Address{
		common.HexToAddress("0xC02aA69..."), // USDC
		common.HexToAddress("0xA0b869915..."), // USDT
		common.HexToAddress("0xdAC17f958..."), // USDT (old)
		common.HexToAddress("0x6B175474E8..."), // DAI
	}

	for _, tokenAddr := range knownERC20s {
		if err := e.querySingleTokenAllowance(ctx, wallet, tokenAddr); err != nil {
			continue
		}
	}

	return approvals, nil
}

// querySingleTokenAllowance checks a single ERC-20 token's allowance.
func (e *ApprovalQueryEngine) querySingleTokenAllowance(ctx context.Context, wallet common.Address, token common.Address) error {
	// This is a simplified example - real implementation would use:
	// 1. Get the spender addresses from storage slot 0
	// 2. Query allowance for each (owner, spender) pair

	// Example: query USDC allowance for wallet
	allowance := new(big.Int)
	
	// Simulated query result - in production, use client.CallContract
	// allowance, err := e.client.CallContract(ctx, callData, wallet)
	
	if allowance.Cmp(big.NewInt(0)) > 0 {
		approvals = append(approvals, &TokenApproval{
			TokenAddress:    token,
			Owner:           wallet,
			Allowance:       allowance,
			Type:            TokenERC20,
			Status:          StatusApproved,
			IsUnlimited:     false,
			BlockNumber:     18500000, // placeholder
			Timestamp:       time.Now(),
		})
	}

	return nil
}

// queryERC721OperatorApprovals fetches all operator approvals for a wallet.
func (e *ApprovalQueryEngine) queryERC721OperatorApprovals(ctx context.Context, wallet common.Address) ([]*TokenApproval, error) {
	var approvals []*TokenApproval

	knownERC721s := []common.Address{
		common.HexToAddress("0xBC4CA0..."), // Bored Ape Yacht Club
		common.HexToAddress("0x60E4d7865..."), // Mutant Ape Yacht Club
	}

	for _, tokenAddr := range knownERC721s {
		operator, err := e.getOperatorForWallet(ctx, wallet, tokenAddr)
		if err != nil || operator == (common.Address{}) {
			continue
		}

		approvals = append(approvals, &TokenApproval{
			TokenAddress:    tokenAddr,
			Owner:           wallet,
			Operator:        &operator,
			Type:            TokenERC721,
			Status:          StatusApproved,
			BlockNumber:     18500000,
			Timestamp:       time.Now(),
		})
	}

	return approvals, nil
}

// queryERC1155OperatorApprovals fetches all operator approvals for a wallet.
func (e *ApprovalQueryEngine) queryERC1155OperatorApprovals(ctx context.Context, wallet common.Address) ([]*TokenApproval, error) {
	var approvals []*TokenApproval

	knownERC1155s := []common.Address{
		common.HexToAddress("0x49d6f..."), // CryptoPunks
	}

	for _, tokenAddr := range knownERC1155s {
		operator, err := e.getOperatorForWallet(ctx, wallet, tokenAddr)
		if err != nil || operator == (common.Address{}) {
			continue
		}

		approvals = append(approvals, &TokenApproval{
			TokenAddress:    tokenAddr,
			Owner:           wallet,
			Operator:        &operator,
			Type:            TokenERC1155,
			Status:          StatusApproved,
			BlockNumber:     18500000,
			Timestamp:       time.Now(),
		})
	}

	return approvals, nil
}

// getOperatorForWallet retrieves the operator address for a wallet on a token.
func (e *ApprovalQueryEngine) getOperatorForWallet(ctx context.Context, wallet common.Address, token common.Address) (common.Address, error) {
	// Simplified - real implementation queries storage slot 0 of the token contract
	return common.HexToAddress("0x000..."), nil
}

// =============================================================================
// RISK SCORING & ANALYSIS
// =============================================================================

// CalculateDrainerExposure computes how much value a wallet could drain.
func (e *ApprovalQueryEngine) CalculateDrainerExposure(ctx context.Context, result *WalletScanResult) (*big.Float, error) {
	total := new(big.Float).SetFloat64(0)

	// ERC-20: sum of unlimited allowances
	for _, approval := range result.Approvals {
		if approval.Type == TokenERC20 && approval.IsUnlimited {
			// Get token price (simplified - use a price feed service in production)
			priceUSD := 1.0 // placeholder

			value := new(big.Float).Mul(approval.Allowance, big.NewFloat(priceUSD))
			total.Add(total, value)
		}
	}

	result.TotalValueUSD = total
	return total, nil
}

// ScoreDrainerRisk assigns a risk level based on exposure and patterns.
func (e *ApprovalQueryEngine) ScoreDrainerRisk(approvals []*TokenApproval) DrainerRiskLevel {
	criticalCount := 0
	mediumCount := 0

	for _, app := range approvals {
		if app.IsUnlimited && app.Type == TokenERC20 {
			criticalCount++
		} else if app.Operator != nil {
			mediumCount++
		}
	}

	switch {
	case criticalCount >= 5:
		return RiskCritical
	case criticalCount >= 1 || mediumCount >= 10:
		return RiskHigh
	case mediumCount >= 3:
		return RiskMedium
	default:
		return RiskLow
	}
}

// =============================================================================
// TRANSACTION BUILDERS
// =============================================================================

// BuildRevokeTxns creates transactions to revoke dangerous approvals.
func (e *ApprovalQueryEngine) BuildRevokeTxns(ctx context.Context, result *WalletScanResult) ([]types.TxData, error) {
	var txns []types.TxData

	for _, approval := range result.Approvals {
		if !approval.IsUnlimited || approval.Status != StatusApproved {
			continue
		}

		tx, err := e.buildERC20RevokeTx(approval)
		if err != nil {
			fmt.Printf("Error building ERC-20 revoke tx: %v\n", err)
			continue
		}

		result.RevokeTxns = append(result.RevokeTxns, *tx)
	}

	return result.RevokeTxns, nil
}

// buildERC20RevokeTx creates a transaction to revoke an ERC-20 allowance.
func (e *ApprovalQueryEngine) buildERC20RevokeTx(approval *TokenApproval) (*types.TxData, error) {
	// Simplified - real implementation would use:
	// 1. Get the spender address from storage slot 0
	// 2. Call setApprovalForUser(spender, 0)

	spender := common.HexToAddress("0x000...") // placeholder

	// Build call data for setApprovalForUser(spender, 0)
	callData := append([]byte{}, 
		0xa905..., // function selector for setApprovalForUser(3 bytes + 20 bytes spender + 8 bytes amount)
		spender.Bytes()...)

	return &types.TxData{
		To:        spender,
		Value:     big.NewInt(0),
		GasLimit:  e.config.GasLimit,
		GasPrice:  new(big.Int).Mul(new(big.Int).SetUint64(e.config.GasPriceGwei*1e9), big.NewInt(1)),
		Data:      callData,
	}, nil
}

// =============================================================================
// RUNNABLE DEMO / ENTRY POINT
// =============================================================================

func main() {
	// Connect to Ethereum network (mainnet for demo)
	client, err := ethclient.Dial("https://ethereum.publicnode.com")
	if err != nil {
		fmt.Printf("Failed to connect to node: %v\n", err)
		os.Exit(1)
	}

	engine, err := NewApprovalQueryEngine(client)
	if err != nil {
		fmt.Printf("Failed to create engine: %v\n", err)
		os.Exit(1)
	}

	// Demo wallet (replace with actual address for testing)
	demoWallet := common.HexToAddress("0x742d35Cc6634C0532925a3b846B4...")

	fmt.Println("=== ApproveWarden: Approval Query Engine Demo ===\n")

	// Step 1: Query all approvals for the demo wallet
	fmt.Println("[1/3] Querying wallet approvals...")
	start := time.Now()

	approvals, err := engine.QueryWalletApprovals(context.Background(), demoWallet)
	if err != nil {
		fmt.Printf("Error querying approvals: %v\n", err)
	} else {
		fmt.Printf("Found %d active approvals in %.2fms\n", len(approvals), start.Sub(time.Now()))

		// Step 2: Analyze and score the results
		fmt.Println("\n[2/3] Analyzing risk profile...")
		
		critical := 0
		unlimitedERC20s := 0
		
		for _, app := range approvals {
			if