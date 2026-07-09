// polyglot/rust/approval_query_engine.rs

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

/// ERC-20/721/1155 approval types with their risk characteristics
#[derive(Debug, Clone, PartialEq)]
pub enum ApprovalType {
    /// Standard ERC-20 token transfer allowance (transferable)
    Transferable(TransferableAllowance),
    /// Non-transferable ERC-20 (e.g., governance tokens)
    NonTransferable,
    /// ERC-721 NFT approval (single or operator)
    NftApproval(NftApproval),
    /// ERC-1155 batch approval
    BatchApproval,
}

/// Transferable allowance metadata - the dangerous kind
#[derive(Debug, Clone)]
pub struct TransferableAllowance {
    pub token_address: String,
    pub spender: String,
    pub amount: u256,
    pub is_infinite: bool,
    pub created_at: SystemTime,
}

/// NFT approval details
#[derive(Debug, Clone)]
pub struct NftApproval {
    pub nft_address: String,
    pub spender: String,
    pub token_id: u64,
    pub is_operator: bool,
    pub operator_is_infinite: bool, // Operator can approve all NFTs
}

/// High-value "drainer" tokens that warrant priority scanning
#[derive(Debug, Clone)]
pub struct DrainerToken {
    pub address: String,
    pub symbol: String,
    pub chain_id: u16,
    /// Minimum amount to flag as significant (in smallest unit)
    pub min_significant_amount: u256,
}

/// Risk score for a single approval/allowance
#[derive(Debug, Clone, Copy)]
pub enum RiskLevel {
    Low = 0,      // Normal, expected behavior
    Medium = 1,   // Slightly unusual but likely safe
    High = 2,     // Potentially dangerous
    Critical = 3, // Active drainer pattern detected
}

impl Default for RiskLevel {
    fn default() -> Self {
        RiskLevel::Low
    }
}

/// Aggregated risk score for a wallet
#[derive(Debug, Clone)]
pub struct WalletRiskScore {
    pub total_score: u32,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub drainer_tokens_found: HashSet<String>,
}

impl Default for WalletRiskScore {
    fn default() -> Self {
        Self {
            total_score: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            drainer_tokens_found: HashSet::new(),
        }
    }
}

/// Configuration for the approval query engine
#[derive(Debug, Clone)]
pub struct QueryEngineConfig {
    /// Drainer tokens to prioritize scanning
    pub drainer_tokens: Vec<DrainerToken>,
    /// Minimum age (seconds) before considering "forgotten"
    pub forgotten_age_threshold: u64,
    /// Maximum amount considered "infinite-like" for non-ERC20s
    pub infinite_allowance_threshold: u256,
}

impl Default for QueryEngineConfig {
    fn default() -> Self {
        Self {
            drainer_tokens: vec![
                DrainerToken {
                    address: "0xA0b86991c6218b36c1d19D4a3e8F0DeA107BD1D5E".to_string(), // USDC
                    symbol: "USDC".to_string(),
                    chain_id: 1,
                    min_significant_amount: u256::from(1_000_000), // $1M
                },
                DrainerToken {
                    address: "0xdAC17F958D2ee523a2206206994597C13d831ec7".to_string(), // USDT
                    symbol: "USDT".to_string(),
                    chain_id: 1,
                    min_significant_amount: u256::from(1_000_000),
                },
            ],
            forgotten_age_threshold: 31536000, // 1 year in seconds
            infinite_allowance_threshold: u256::MAX / 4,
        }
    }
}

/// Result of scanning a single wallet
#[derive(Debug, Clone)]
pub struct WalletScanResult {
    pub address: String,
    pub scan_timestamp: SystemTime,
    pub total_approvals: usize,
    pub total_allowances: usize,
    pub risk_score: WalletRiskScore,
    pub approvals: Vec<Approval>,
    pub allowances: Vec<Allowance>,
    pub nft_approvals: Vec<NftApproval>,
    pub recommended_revokes: Vec<TransactionRevoke>,
}

/// A single approval record
#[derive(Debug, Clone)]
pub struct Approval {
    pub id: String,
    pub token_address: String,
    pub spender: String,
    pub amount: u256,
    pub is_infinite: bool,
    pub created_at: SystemTime,
    pub risk_level: RiskLevel,
    pub notes: Vec<String>,
}

/// A single allowance record (transferable)
#[derive(Debug, Clone)]
pub struct Allowance {
    pub id: String,
    pub token_address: String,
    pub spender: String,
    pub amount: u256,
    pub is_infinite: bool,
    pub created_at: SystemTime,
    pub risk_level: RiskLevel,
}

/// Transaction to revoke an approval/allowance
#[derive(Debug, Clone)]
pub struct TransactionRevoke {
    pub id: String,
    pub token_address: String,
    pub spender: String,
    pub amount: u256,
    pub is_infinite: bool,
    pub method: String,
    pub estimated_gas: u64,
    pub priority: i32, // Higher = more urgent
}

/// Scanner for ERC-20/721/1155 approvals and allowances
pub struct ApprovalQueryEngine {
    config: QueryEngineConfig,
}

impl ApprovalQueryEngine {
    /// Create a new engine with custom configuration
    pub fn new(config: Option<QueryEngineConfig>) -> Self {
        Self {
            config: config.unwrap_or_default(),
        }
    }

    /// Set the drainer tokens list
    pub fn set_drainer_tokens(&mut self, tokens: Vec<DrainerToken>) {
        self.config.drainer_tokens = tokens;
    }

    /// Scan a wallet address for all approvals and allowances
    /// 
    /// This is a simulated scan - in production this would query Etherscan API.
    pub fn scan_wallet(&self, address: &str) -> WalletScanResult {
        // Simulated data - replace with actual API calls
        let (approvals, allowances, nft_approvals) = Self::simulate_scan(address);

        let risk_score = self.calculate_risk_score(
            &approvals, 
            &allowances, 
            &nft_approvals
        );

        // Generate recommended revokes for high/critical items
        let revokes = self.generate_revokes(&approvals, &allowances, &nft_approvals);

        WalletScanResult {
            address: address.to_string(),
            scan_timestamp: SystemTime::now(),
            total_approvals: approvals.len(),
            total_allowances: allowances.len(),
            risk_score,
            approvals,
            allowances,
            nft_approvals,
            recommended_revokes: revokes,
        }
    }

    /// Simulate scanning a wallet (replace with real API calls)
    fn simulate_scan(address: &str) -> (Vec<Approval>, Vec<Allowance>, Vec<NftApproval>) {
        // This simulates what the scanner would find
        let mut approvals = Vec::new();
        let mut allowances = Vec::new();

        // Add some realistic sample data for demonstration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();

        // Sample: Infinite USDC allowance (high risk)
        if address.contains("0x") {
            allowances.push(Allowance {
                id: format!("allow_{}", address.len()),
                token_address: "0xA0b86991c6218b36c1d19D4a3e8F0DeA107BD1D5E".to_string(),
                spender: address.to_string(),
                amount: u256::MAX,
                is_infinite: true,
                created_at: now - 86400 * 7, // 7 days ago
                risk_level: RiskLevel::Critical,
            });

            // Sample: Normal ERC-20 approval (low risk)
            approvals.push(Approval {
                id: "app_1".to_string(),
                token_address: "0x6B175474E89094C44Da98b950Ede36dF6193DAeD".to_string(), // DAI
                spender: address.to_string(),
                amount: u256::from(1_000_000),
                is_infinite: false,
                created_at: now - 86400 * 30,
                risk_level: RiskLevel::Low,
                notes: vec!["Normal DAI approval".to_string()],
            });

            // Sample: Medium risk - older infinite allowance
            allowances.push(Allowance {
                id: "allow_2".to_string(),
                token_address: "0xC02aA394e8a6D7E8C5B1Fb6f8c7d4c3b2a1f0e9d".to_string(), // WETH
                spender: address.to_string(),
                amount: u256::MAX,
                is_infinite: true,
                created_at: now - 86400 * 365, // 1 year ago
                risk_level: RiskLevel::High,
            });

            // Sample: NFT approval (medium risk if operator)
            nft_approvals.push(NftApproval {
                nft_address: "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D".to_string(), // Bored Ape
                spender: address.to_string(),
                token_id: 1234,
                is_operator: true,
                operator_is_infinite: false,
            });
        }

        (approvals, allowances, nft_approvals)
    }

    /// Calculate comprehensive risk score for a wallet
    fn calculate_risk_score(
        &self,
        approvals: &[Approval],
        allowances: &[Allowance],
        nfts: &[NftApproval],
    ) -> WalletRiskScore {
        let mut score = WalletRiskScore::default();

        // Score each allowance (transferable)
        for allow in allowances.iter() {
            match allow.risk_level {
                RiskLevel::Critical => {
                    score.total_score += 100;
                    score.critical_count += 1;
                    if !allow.token_address.is_empty() && 
                       !self.config.drainer_tokens.iter().any(|d| d.address == allow.token_address) {
                        score.drainer_tokens_found.insert(allow.token_address.clone());
                    }
                },
                RiskLevel::High => {
                    score.total_score += 50;
                    score.high_count += 1;
                },
                RiskLevel::Medium => {
                    score.total_score += 25;
                    score.medium_count += 1;
                },
                _ => {
                    score.low_count += 1;
                }
            }

            // Bonus points for infinite allowances
            if allow.is_infinite && !allow.token_address.is_empty() {
                let is_drainer = self.config.drainer_tokens.iter().any(|d| d.address == allow.token_address);
                if is_drainer {
                    score.total_score += 20;
                } else {
                    score.total_score += 10;
                }
            }

            // Bonus for old allowances (forgotten approvals)
            let age_seconds = match allow.created_at.duration_since(UNIX_EPOCH) {
                Ok(d) => d.as_secs(),
                Err(_) => 0,
            };
            if age_seconds > self.config.forgotten_age_threshold {
                score.total_score += 15;
            }
        }

        // Score each approval
        for app in approvals.iter() {
            match app.risk_level {
                RiskLevel::Critical => {
                    score.total_score += 80;
                    score.critical_count += 1;
                },
                RiskLevel::High => {
                    score.total_score += 40;
                    score.high_count += 1;
                },
                _ => {}
            }

            // Infinite approval is always concerning
            if app.is_infinite {
                score.total_score += 30;
            }
        }

        // Score NFT approvals
        for nft in nfts.iter() {
            if nft.is_operator && nft.operator_is_infinite {
                score.total_score += 60;
                score.high_count += 1;
            } else if nft.is_operator {
                score.total_score += 20;
            }
        }

        // Cap the total score at a reasonable maximum
        let max_score = 500;
        if score.total_score > max_score {
            score.total_score = max_score;
        }

        score
    }

    /// Generate recommended revoke transactions
    fn generate_revokes(
        &self,
        approvals: &[Approval],
        allowances: &[Allowance],
        nfts: &[NftApproval],
    ) -> Vec<TransactionRevoke> {
        let mut revokes = Vec::new();

        // Collect all items that need revoking (high/critical risk)
        let mut candidates: Vec<(&Allowance, &RiskLevel)> = allowances.iter()
            .filter(|a| matches!(a.risk_level, RiskLevel::Critical | RiskLevel::High))
            .map(|(a, l)| (a, l))
            .collect();

        // Add infinite allowances regardless of risk level
        candidates.extend(approvals.iter().filter_map(|a| {
            if a.is_infinite && matches!(a.risk_level, RiskLevel::High | RiskLevel::Critical) {
                Some((a, &a.risk_level))
            } else {
                None
            }
        }));

        // Sort by risk level (critical first) then by age (older = forgotten)
        candidates.sort_by(|(a1, l1), (a2, l2)| {
            let priority_score_1 = match *l1 {
                RiskLevel::Critical => 400,
                RiskLevel::High => 300,
                _ => 100,
            };
            let priority_score_2 = match *l2 {
                RiskLevel::Critical => 400,
                RiskLevel::High => 300,
                _ => 100,
            };

            // Primary: risk level, Secondary: age (older first for forgotten)
            priority_score_2.cmp(&priority_score_1).then_with(|| {
                let age_1 = match a1.created_at.duration_since(UNIX_EPOCH) {
                    Ok(d) => d.as_secs(),
                    Err(_) => 0,
                };
                let age_2 = match a2.created_at.duration_since(UNIX_EPOCH) {
                    Ok(d) => d.as_secs(),
                    Err(_) => 0,
                };
                age_1.cmp(&age_2)
            })
        });

        // Deduplicate by spender + token
        let mut seen = HashSet::new();
        for (allowance, _) in candidates {
            if !seen.insert((allowance.spender.clone(), allowance.token_address.clone())) {
                continue;
            }

            revokes.push(TransactionRevoke {
                id: format!("revoke_{}", allow_id(&allowance)),
                token_address: