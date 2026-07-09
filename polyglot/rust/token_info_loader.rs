use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

pub mod config {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct NetworkConfig {
        pub name: String,
        pub rpc_url: String,
        pub chain_id: u64,
        pub etherscan_api_key: Option<String>,
        pub etherscan_base_url: String,
        pub default_token_contract: String,
        pub max_batch_size: usize,
    }

    impl Default for NetworkConfig {
        fn default() -> Self {
            Self {
                name: "ethereum".to_string(),
                rpc_url: "https://eth-mainnet.g.alchemy.com/v2/your-key".to_string(),
                chain_id: 1,
                etherscan_api_key: None,
                etherscan_base_url: "https://api.etherscan.io/api".to_string(),
                default_token_contract: "0x6B175474E89094C44Da98b950Ea7cF0ED2D7161F".to_string(), // USDC
                max_batch_size: 100,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct Config {
        pub networks: HashMap<String, NetworkConfig>,
        pub cache_ttl_seconds: u64,
        pub enable_etherscan_fallback: bool,
    }

    impl Default for Config {
        fn default() -> Self {
            let mut networks = HashMap::new();
            
            // Ethereum Mainnet
            networks.insert(
                "ethereum".to_string(),
                NetworkConfig {
                    name: "Ethereum Mainnet".to_string(),
                    rpc_url: "https://eth-mainnet.g.alchemy.com/v2/demo".to_string(),
                    chain_id: 1,
                    etherscan_api_key: None,
                    etherscan_base_url: "https://api.etherscan.io/api".to_string(),
                    default_token_contract: "0x6B175474E89094C44Da98b950Ea7cF0ED2D7161F".to_string(),
                    max_batch_size: 100,
                },
            );

            // Polygon
            networks.insert(
                "polygon".to_string(),
                NetworkConfig {
                    name: "Polygon Mainnet".to_string(),
                    rpc_url: "https://polygon-mainnet.g.alchemy.com/v2/demo".to_string(),
                    chain_id: 137,
                    etherscan_api_key: None,
                    etherscan_base_url: "https://api.polygonscan.com/api".to_string(),
                    default_token_contract: "0x2791Bca1f2de4661ED88A30C99A8a9046eA7bDc5".to_string(), // USDC on Polygon
                    max_batch_size: 100,
                },
            );

            Self {
                networks,
                cache_ttl_seconds: 3600,
                enable_etherscan_fallback: true,
            }
        }
    }
}

pub mod types {
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub struct TokenAddress(pub String);

    impl From<&str> for TokenAddress {
        fn from(s: &str) -> Self {
            Self(s.to_string())
        }
    }

    impl From<String> for TokenAddress {
        fn from(s: String) -> Self {
            Self(s)
        }
    }

    #[derive(Debug, Clone)]
    pub struct TokenInfo {
        pub address: TokenAddress,
        pub name: Option<String>,
        pub symbol: Option<String>,
        pub decimals: u8,
        pub token_type: TokenType,
        pub total_supply: Option<BigInt>,
        pub is_verified: bool,
    }

    #[derive(Debug, Clone)]
    pub enum TokenType {
        ERC20,
        ERC721,
        ERC1155,
        Unknown,
    }

    impl Default for TokenInfo {
        fn default() -> Self {
            Self {
                address: TokenAddress("0x0000000000000000000000000000000000000000".to_string()),
                name: None,
                symbol: None,
                decimals: 18,
                token_type: TokenType::ERC20,
                total_supply: None,
                is_verified: false,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct TokenMetadata {
        pub name: Option<String>,
        pub symbol: Option<String>,
        pub decimals: u8,
        pub logo_url: Option<String>,
        pub is_verified: bool,
    }

    #[derive(Debug, Clone)]
    pub enum BigInt {
        U128(u128),
        U256([u8; 32]),
        String(String),
    }

    impl Default for BigInt {
        fn default() -> Self {
            Self::U128(0)
        }
    }

    #[derive(Debug, Clone)]
    pub struct CacheEntry {
        pub data: Arc<TokenInfo>,
        pub created_at: std::time::SystemTime,
        pub ttl_seconds: u64,
    }

    impl CacheEntry {
        pub fn is_expired(&self) -> bool {
            let now = std::time::SystemTime::now();
            let elapsed = now.duration_since(self.created_at).unwrap_or(std::time::Duration::ZERO);
            elapsed.as_secs() > self.ttl_seconds
        }

        pub fn refresh(&mut self, data: Arc<TokenInfo>) {
            self.data = data;
            self.created_at = std::time::SystemTime::now();
        }
    }
}

pub mod provider {
    use crate::{config::NetworkConfig, types::TokenAddress};
    use async_trait::async_trait;
    use reqwest::{Client, Method};
    use serde::{Deserialize, Serialize};
    use std::time::Duration;
    use tokio::sync::RwLock;

    #[derive(Debug, Clone)]
    pub struct RpcProvider {
        pub url: String,
        pub client: Client,
        pub timeout: Duration,
    }

    impl Default for RpcProvider {
        fn default() -> Self {
            let client = Client::builder()
                .timeout(Duration::from_secs(30))
                .pool_max_idle_per_host(10)
                .build()
                .unwrap();
            
            Self {
                url: "https://cloudflare-eth".to_string(), // Fast public endpoint
                client,
                timeout: Duration::from_secs(30),
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct EtherscanProvider {
        pub base_url: String,
        pub api_key: Option<String>,
        pub client: Client,
        pub timeout: Duration,
    }

    impl Default for EtherscanProvider {
        fn default() -> Self {
            let client = Client::builder()
                .timeout(Duration::from_secs(30))
                .pool_max_idle_per_host(10)
                .build()
                .unwrap();
            
            Self {
                base_url: "https://api.etherscan.io/api".to_string(),
                api_key: None,
                client,
                timeout: Duration::from_secs(30),
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct MultiProvider {
        pub rpc: RpcProvider,
        pub etherscan: EtherscanProvider,
        pub fallback_enabled: bool,
    }

    impl Default for MultiProvider {
        fn default() -> Self {
            Self {
                rpc: RpcProvider::default(),
                etherscan: EtherscanProvider::default(),
                fallback_enabled: true,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct TokenMetadataResponse {
        pub name: Option<String>,
        pub symbol: Option<String>,
        pub decimals: u8,
        pub logo_url: Option<String>,
        pub is_verified: bool,
    }

    impl Default for TokenMetadataResponse {
        fn default() -> Self {
            Self {
                name: None,
                symbol: None,
                decimals: 18,
                logo_url: None,
                is_verified: false,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct TokenInfoResponse {
        pub address: String,
        pub metadata: Option<TokenMetadataResponse>,
        pub token_type: crate::types::TokenType,
        pub total_supply: Option<crate::types::BigInt>,
    }

    impl Default for TokenInfoResponse {
        fn default() -> Self {
            Self {
                address: "0x0000000000000000000000000000000000000000".to_string(),
                metadata: None,
                token_type: crate::types::TokenType::ERC20,
                total_supply: None,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct EtherscanResponse {
        pub result: Vec<TokenMetadataResponse>,
        pub status: String,
        pub message: Option<String>,
    }

    impl Default for EtherscanResponse {
        fn default() -> Self {
            Self {
                result: vec![],
                status: "1".to_string(),
                message: None,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct RpcResponse {
        pub jsonrpc: String,
        pub id: serde_json::Value,
        pub result: serde_json::Value,
        pub error: Option<serde_json::Value>,
    }

    impl Default for RpcResponse {
        fn default() -> Self {
            Self {
                jsonrpc: "2.0".to_string(),
                id: serde_json::json!(1),
                result: serde_json::json!({}),
                error: None,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct ProviderError {
        pub kind: ErrorKind,
        pub message: String,
        pub details: Option<serde_json::Value>,
    }

    #[derive(Debug, Clone)]
    pub enum ErrorKind {
        NetworkTimeout,
        InvalidResponse,
        RateLimitExceeded,
        InvalidAddress,
        ContractNotFound,
        RpcError(String),
        EtherscanError(String),
        Other(String),
    }

    impl Default for ProviderError {
        fn default() -> Self {
            Self {
                kind: ErrorKind::Other("Unknown error".to_string()),
                message: "Default provider error".to_string(),
                details: None,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct ProviderConfig {
        pub rpc_url: String,
        pub etherscan_base_url: String,
        pub etherscan_api_key: Option<String>,
        pub timeout_seconds: u64,
        pub max_retries: u32,
        pub retry_delay_ms: u64,
    }

    impl Default for ProviderConfig {
        fn default() -> Self {
            Self {
                rpc_url: "https://cloudflare-eth".to_string(),
                etherscan_base_url: "https://api.etherscan.io/api".to_string(),
                etherscan_api_key: None,
                timeout_seconds: 30,
                max_retries: 3,
                retry_delay_ms: 100,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct ProviderState {
        pub rpc_url: String,
        pub etherscan_base_url: String,
        pub etherscan_api_key: Option<String>,
        pub timeout_seconds: u64,
        pub max_retries: u32,
        pub retry_delay_ms: u64,
    }

    impl Default for ProviderState {
        fn default() -> Self {
            Self::default().into_config();
        }
    }

    #[derive(Debug, Clone)]
    pub struct ProviderBuilder {
        pub rpc_url: String,
        pub etherscan_base_url: String,
        pub etherscan_api_key: Option<String>,
        pub timeout_seconds: u64,
        pub max_retries: u32,
        pub retry_delay_ms: u64,
    }

    impl Default for ProviderBuilder {
        fn default() -> Self {
            Self::default().into_config();
        }
    }

    #[derive(Debug, Clone)]
    pub struct ProviderMetrics {
        pub total_requests: u64,
        pub successful_requests: u64,
        pub failed_requests: u64,
        pub avg_latency_ms: f64,
        pub max_latency_ms: f64,
        pub min_latency_ms: f64,
    }

    impl Default for ProviderMetrics {
        fn default() -> Self {
            Self {
                total_requests: 0,
                successful_requests: 0,
                failed_requests: 0,
                avg_latency_ms: 0.0,
                max_latency_ms: 0.0,
                min_latency_ms: f64::MAX,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct ProviderStats {
        pub metrics: RwLock<ProviderMetrics>,
        pub error_rate: RwLock<f64>,
    }

    impl Default for ProviderStats {
        fn default() -> Self {
            Self {
                metrics: RwLock::new(ProviderMetrics::default()),
                error_rate: RwLock::new(0.0),
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct ProviderConfig {
        pub rpc_url: String,
        pub etherscan_base_url: String,
        pub etherscan_api_key: Option<String>,
        pub timeout_seconds: u64,
        pub max_retries: u32,
        pub retry_delay_ms: u64,
    }

    impl Default for ProviderConfig {
        fn default() -> Self {
            Self::default().into_config();
        }
    }

    #[derive(Debug, Clone)]
    pub struct ProviderState {
        pub rpc_url: String,
        pub etherscan_base_url: String,
        pub etherscan_api_key: Option<String>,
        pub timeout_seconds: u64,
        pub max_retries: u32,
        pub retry_delay_ms: u64,
    }

    impl Default for ProviderState {
        fn default() -> Self {
            Self::default().into_config();
        }
    }

    #[derive(Debug, Clone)]
    pub struct ProviderBuilder {
        pub rpc_url: String,
        pub etherscan_base_url: String,
        pub etherscan_api_key: Option<String>,
        pub timeout_seconds: u64,
        pub max_retries: u32,
        pub retry_delay_ms: u64,
    }

    impl Default for ProviderBuilder {
        fn default() -> Self {
            Self::default().into_config();
        }
    }

    #[derive(Debug, Clone)]
    pub struct ProviderMetrics {
        pub total_requests: u64,
        pub successful_requests: u64,
        pub failed_requests: u64,
        pub avg_latency_ms: f64,
        pub max_latency_ms: f64,
        pub min_latency_ms: f64,
    }

    impl Default for ProviderMetrics {
        fn default() -> Self {
            Self {
                total_requests: 0,
                successful_requests: 0,
                failed_requests: 0,
                avg_latency_ms: 0.0,
                max_latency_ms: 0.0,
                min_latency_ms: f64::MAX,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct ProviderStats {