package token_info_loader

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

// TokenInfo represents loaded metadata for a single token
type TokenInfo struct {
	Address      common.Address
	Name         string
	Symbol       string
	Decimals     uint8
	Balance      *big.Int
	Allowances   []ApprovalInfo
	RiskScore    float64
	LastUpdated  time.Time
}

// ApprovalInfo represents a token allowance to another contract
type ApprovalInfo struct {
	Spender         common.Address
	Amount          *big.Int
	IsInfinite      bool
	IsHighRisk      bool
	SpenderCategory string // "DEX", "Bridge", "Unknown", etc.
}

// TokenLoader handles loading and analyzing token information for a wallet
type TokenLoader struct {
	client     *ethclient.Client
	cacheDir   string
	updateFreq time.Duration
	mu         sync.RWMutex
	cache      map[common.Address]*TokenInfo
}

// NewTokenLoader creates a new loader instance with the provided client
func NewTokenLoader(client *ethclient.Client, cacheDir string) *TokenLoader {
	return &TokenLoader{
		client:     client,
		cacheDir:   cacheDir,
		updateFreq: 5 * time.Minute,
		cache:      make(map[common.Address]*TokenInfo),
	}
}

// LoadTokenInfo fetches and analyzes a single token's information for the given wallet
func (l *TokenLoader) LoadTokenInfo(ctx context.Context, wallet common.Address, tokenAddr common.Address) (*TokenInfo, error) {
	l.mu.RLock()
	if cached, exists := l.cache[tokenAddr]; exists && time.Since(cached.LastUpdated) < 5*time.Minute {
		l.mu.RUnlock()
		return cached, nil
	}
	l.mu.RUnlock()

	info := &TokenInfo{
		Address:   tokenAddr,
		LastUpdated: time.Now(),
	}

	// Fetch basic token metadata from the contract
	metadata, err := l.fetchMetadata(ctx, tokenAddr)
	if err != nil {
		return info, fmt.Errorf("failed to fetch metadata: %w", err)
	}
	info.Name = metadata.Name
	info.Symbol = metadata.Symbol
	info.Decimals = metadata.Decimals

	// Fetch wallet balance for this token
	balance, err := l.fetchBalance(ctx, wallet, tokenAddr)
	if err != nil {
		return info, fmt.Errorf("failed to fetch balance: %w", err)
	}
	info.Balance = balance

	// Analyze allowances (who has approved the wallet's tokens)
	allowances, err := l.fetchAllowances(ctx, wallet, tokenAddr)
	if err != nil {
		return info, fmt.Errorf("failed to fetch allowances: %w", err)
	}
	info.Allowances = allowances

	// Calculate risk score
	info.RiskScore = l.calculateRiskScore(info)

	l.mu.Lock()
	l.cache[tokenAddr] = info
	l.mu.Unlock()

	return info, nil
}

// LoadAllTokenInfo loads information for all tokens a wallet holds above the threshold
func (l *TokenLoader) LoadAllTokenInfo(ctx context.Context, wallet common.Address, minBalance *big.Int) ([]*TokenInfo, error) {
	var mu sync.Mutex
	type result struct {
		info    *TokenInfo
		err     error
	}

	// Fetch all token balances first
	balances, err := l.fetchAllBalances(ctx, wallet)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch all balances: %w", err)
	}

	var wg sync.WaitGroup
	results := make(chan result, len(balances))

	for _, balance := range balances {
		wg.Add(1)
		go func(addr common.Address, bal *big.Int) {
			defer wg.Done()
			
			if bal.Cmp(minBalance) < 0 {
				return
			}

			info, err := l.LoadTokenInfo(ctx, wallet, addr)
			results <- result{info: info, err: err}
		}(balance.Address, balance.Balance)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var infos []*TokenInfo
	for r := range results {
		if r.err == nil && r.info != nil {
			infos = append(infos, r.info)
		}
	}

	return infos, nil
}

// fetchMetadata retrieves the ERC-20 metadata from a contract
func (l *TokenLoader) fetchMetadata(ctx context.Context, addr common.Address) (*Metadata, error) {
	metadata := &Metadata{
		Address: addr.Hex(),
	}

	// Standard ERC-20 name query
	nameRes, err := l.client.CallContext(ctx, nil, "name", addr)
	if err == nil && len(nameRes) > 0 {
		metadata.Name = string(nameRes)
	}

	// Standard ERC-20 symbol query
	symbolRes, err := l.client.CallContext(ctx, nil, "symbol", addr)
	if err == nil && len(symbolRes) > 0 {
		metadata.Symbol = string(symbolRes)
	}

	// Standard ERC-20 decimals query
	decimalsRes, err := l.client.CallContext(ctx, nil, "decimals", addr)
	if err == nil && len(decimalsRes) > 0 {
		decimals, _ := new(big.Int).SetBytes(decimalsRes).Uint64()
		metadata.Decimals = uint8(decimals % 256)
	}

	return metadata, nil
}

// fetchBalance retrieves the token balance for a specific wallet
func (l *TokenLoader) fetchBalance(ctx context.Context, wallet common.Address, tokenAddr common.Address) (*big.Int, error) {
	balanceRes, err := l.client.CallContext(ctx, nil, "balanceOf", wallet, tokenAddr)
	if err != nil {
		return big.NewInt(0), fmt.Errorf("call failed: %w", err)
	}

	return new(big.Int).SetBytes(balanceRes), nil
}

// fetchAllowances retrieves all allowances where the wallet is the spender
func (l *TokenLoader) fetchAllowances(ctx context.Context, wallet common.Address, tokenAddr common.Address) ([]ApprovalInfo, error) {
	var mu sync.Mutex
	allowances := make([]ApprovalInfo, 0)

	// Query for each unique spender - we'll use a reasonable limit
	spenderLimit := 100
	
	for i := 0; i < spenderLimit; i++ {
		spenderAddr := common.HexToAddress(fmt.Sprintf("%s%d", "0x", hex.EncodeToString(append([]byte{byte(i)}, wallet.Bytes()...)))[:20])
		
		amountRes, err := l.client.CallContext(ctx, nil, "allowance", tokenAddr, spenderAddr)
		if err != nil {
			continue
		}

		// Check if this spender has an allowance to the wallet's tokens
		spenderAllowance := new(big.Int).SetBytes(amountRes)
		
		// If spender can move more than 1 token (allowing for decimals), flag it
		if spenderAllowance.Cmp(big.NewInt(1)) > 0 {
			isInfinite := spenderAllowance.Cmp(l.getDecimalsMultiplier(tokenAddr)) >= 0
			
			info := ApprovalInfo{
				Spender:    spenderAddr,
				Amount:     new(big.Int).Set(amountRes),
				IsInfinite: isInfinite,
			}

			// Categorize the spender
			info.SpenderCategory = l.categorizeSpender(spenderAddr)
			
			if isInfinite || info.SpenderCategory == "DEX" || info.SpenderCategory == "Bridge" {
				info.IsHighRisk = true
			}

			mu.Lock()
			allowances = append(allowances, info)
			mu.Unlock()
		}
	}

	return allowances, nil
}

// fetchAllBalances retrieves all ERC-20 token balances for a wallet
func (l *TokenLoader) fetchAllBalances(ctx context.Context, wallet common.Address) ([]BalanceInfo, error) {
	balances := make([]BalanceInfo, 0)

	// Use the standard "all tokens" query pattern
	query := []interface{}{wallet}
	
	for i := 0; i < 100; i++ {
		result, err := l.client.CallContext(ctx, nil, "balanceOf", wallet, common.HexToAddress(fmt.Sprintf("0x%04d00000000000000000000000000000000000000000000000000000000000", i)))
		if err != nil {
			continue
		}

		balance := new(big.Int).SetBytes(result)
		
		// Skip zero balances and the native ETH balance (first result is usually ETH)
		if balance.Cmp(big.NewInt(0)) > 0 && i > 0 {
			addr := common.HexToAddress(fmt.Sprintf("0x%04d", i))
			
			balances = append(balances, BalanceInfo{
				Address:   addr,
				Balance:   balance,
				IsNative:  false,
			})
		}

		if result == nil {
			break
		}
	}

	return balances, nil
}

// getDecimalsMultiplier returns the max amount for a token given its decimals
func (l *TokenLoader) getDecimalsMultiplier(addr common.Address) *big.Int {
	metadata := l.fetchMetadata(context.Background(), addr)
	if metadata == nil || metadata.Decimals == 0 {
		return big.NewInt(1e18) // Default to 18 decimals
	}

	multiplier := new(big.Int).Exp(big.NewInt(10), new(big.Int).SetUint64(metadata.Decimals), nil)
	return multiplier
}

// calculateRiskScore computes a risk score (0-100) for a token based on its allowances
func (l *TokenLoader) calculateRiskScore(info *TokenInfo) float64 {
	score := 0.0

	// Factor 1: Infinite approvals
	infiniteCount := 0
	for _, allow := range info.Allowances {
		if allow.IsInfinite {
			infiniteCount++
			score += 15.0 // +15 per infinite approval
		}
	}

	// Factor 2: High-risk spenders (DEXs, bridges)
	highRiskSpenderCount := 0
	for _, allow := range info.Allowances {
		if allow.IsHighRisk || allow.SpenderCategory == "DEX" || allow.SpenderCategory == "Bridge" {
			highRiskSpenderCount++
			score += 10.0 // +10 per high-risk spender
		}
	}

	// Factor 3: Large balance exposed to risky contracts
	if info.Balance.Cmp(big.NewInt(1e18)) > 0 { // More than 1 token
		riskyRatio := float64(highRiskSpenderCount) / float64(len(info.Allowances)+1)
		score += riskyRatio * 25.0
	}

	// Factor 4: Unknown spenders (not categorized)
	unknownCount := 0
	for _, allow := range info.Allowances {
		if allow.SpenderCategory == "Unknown" {
			unknownCount++
			score += 3.0 // +3 per unknown spender
		}
	}

	// Cap at 100
	if score > 100.0 {
		score = 100.0
	}

	return score
}

// categorizeSpender attempts to identify what type of contract a spender is
func (l *TokenLoader) categorizeSpender(spender common.Address) string {
	knownContracts := map[common.Address]string{
		common.HexToAddress("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"): "DEX", // Uniswap V2 Router
		common.HexToAddress("0xd9e14ef9f2aE8b0c09B0CE4266739d38cC8432dA"): "DEX", // Uniswap V3 Pool
		common.HexToAddress("0xE592427A0AEe2E1Ff2a41D87b818F0feCa409188"): "DEX", // Uniswap V2 Router (old)
		common.HexToAddress("0x68b346584f6000cd2b0805e8482d29a1ab76f8ed"): "DEX", // Uniswap V3 Multicall
		common.HexToAddress("0xb1fE6DcF3A5BDbE871C85c96E5b77F740792c16e"): "Bridge", // Polygon Bridge
		common.HexToAddress("0x4200000000000000000000000000000000000006"): "DEX",  // Arbitrum L2 Router
	}

	if _, exists := knownContracts[spender]; exists {
		return knownContracts[spender]
	}

	// Check if spender is a contract (has code)
	code, err := l.client.CodeAt(context.Background(), spender, nil)
	if err != nil || len(code) == 0 {
		return "Unknown"
	}

	// Simple heuristic: if it's a known DEX/bridge pattern, use that
	hash := sha256.Sum256(spender.Bytes())
	if hash[0] < 10 && hash[1] > 200 {
		return "DEX" // Heuristic for common DEX routers
	}

	return "Unknown"
}

// BalanceInfo represents a wallet's balance of a specific token
type BalanceInfo struct {
	Address   common.Address
	Balance   *big.Int
	IsNative  bool
}

// Metadata contains the basic ERC-20 metadata for a token
type Metadata struct {
	Address    string
	Name       string
	Symbol     string
	Decimals   uint8
}

// ScanWallet performs a full scan of a wallet's token holdings and approvals
func (l *TokenLoader) ScanWallet(ctx context.Context, wallet common.Address, minBalance *big.Int) ([]*TokenInfo, error) {
	return l.LoadAllTokenInfo(ctx, wallet, minBalance)
}

// GetCachedInfo retrieves cached info for a token if available
func (l *TokenLoader) GetCachedInfo(tokenAddr common.Address) (*TokenInfo, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if info, exists := l.cache[tokenAddr]; exists {
		return info, true
	}
	return nil, false
}

// ClearCache removes all cached token information
func (l *TokenLoader) ClearCache() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cache = make(map[common.Address]*TokenInfo)
}

// Demo function to test the loader with a sample wallet
func main() {
	// Connect to Ethereum mainnet
	client, err := ethclient.Dial("https://eth-mainnet.g.alchemy.com/v2/demo")
	if err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		return
	}

	defer client.Close()

	loader := NewTokenLoader(client, "/tmp/approvewarden_cache")

	// Sample wallet with known token holdings
	sampleWallet := common.HexToAddress("0x8ba1f189554d23da7b6db4deea68c3c5a4fb3fae") // Vitalik's wallet

	fmt.Println("=== ApproveWarden Token Info Loader Demo ===\n")
	fmt.Printf("Scanning wallet: %s\n", sampleWallet.Hex())

	// Load all tokens above 0.1 ETH equivalent (roughly 2000 tokens for most ERC-20s)
	minBalance := big.NewInt(2000)
	
	infos, err := loader.ScanWallet(context.Background(), sampleWallet, minBalance)
	if err != nil {
		fmt.Printf("Scan error: %v\n", err)
		return
	}

	fmt.Printf("\nFound %d tokens with balance > 2000:\n", len(infos))

	for i, info := range infos {
		fmt.Printf("\n[%d] Token: %s (%s)\n", i+1, info.Symbol, info.Address.Hex())
		fmt.Printf("    Decimals: %d