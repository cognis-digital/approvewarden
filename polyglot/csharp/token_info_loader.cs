using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace ApproveWarden.Core
{
    /// <summary>
    /// Configuration for token info loader behavior.
    /// </summary>
    public class TokenInfoLoaderConfig
    {
        public const string DefaultNetwork = "ethereum";
        
        public static readonly HttpClient DefaultHttpClient = new()
        {
            Timeout = TimeSpan.FromSeconds(30),
            MaxResponseContentBufferSize = 1024 * 1024, // 1MB
            DefaultHeaders = 
            {
                { "Accept", "application/json" },
                { "User-Agent", "ApproveWarden/1.0" }
            }
        };

        public string NetworkName { get; set; } = DefaultNetwork;
        public string ApiKey { get; set; } // Etherscan API key, optional
        public int CacheTtlMinutes { get; set; } = 60;
        public int MaxRetries { get; set; } = 3;
        public TimeSpan RetryDelay { get; set; } = TimeSpan.FromSeconds(1);
    }

    /// <summary>
    /// Represents a loaded token with metadata and risk indicators.
    /// </summary>
    public class TokenInfo
    {
        public string NetworkName { get; set; }
        public string ContractAddress { get; set; }
        public string Name { get; set; }
        public string Symbol { get; set; }
        public int Decimals { get; set; }
        public bool IsVerified { get; set; }
        public DateTime VerifiedAt { get; set; }
        public TokenRiskLevel RiskLevel { get; set; }
        public List<string> KnownIssues { get; set; } = new();
        public long TotalSupply { get; set; }
        public string SourceCode { get; set; }
        public string CompilerVersion { get; set; }

        public static TokenInfo CreateEmpty(string address, string network)
        {
            return new TokenInfo
            {
                NetworkName = network,
                ContractAddress = address,
                RiskLevel = TokenRiskLevel.Unknown,
                VerifiedAt = DateTime.UtcNow
            };
        }
    }

    /// <summary>
    /// Risk classification for loaded tokens.
    /// </summary>
    public enum TokenRiskLevel
    {
        Safe,              // Verified, known contract, good history
        Unknown,           // Not found or minimal data
        Suspicious,        // Some red flags detected
        DrainerCandidate,  // Known drainer pattern
        Honeypot,          // Likely honeypot
        Exploit,           // Recently exploited
        Scam               // Known scam contract
    }

    /// <summary>
    /// Predefined known drainer/honeypot addresses by network.
    /// </summary>
    public static class TokenBlacklist
    {
        private static readonly ConcurrentDictionary<string, HashSet<string>> _blacklist = new();

        public static void Initialize()
        {
            // Ethereum mainnet known drainers (sample set)
            var ethMainnet = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "0x1f98431c8ad98523631ae4a59f267346ea31f984", // UNI (example - verify actual drainers)
                "0x7d1afa7b718fb893db30a3abc0cfc6cc8ccdada3", // USDC (example)
            };

            _blacklist[TokenInfoLoaderConfig.DefaultNetwork] = ethMainnet;
        }

        public static bool IsBlacklisted(string address, string network)
        {
            if (_blacklist.TryGetValue(network, out var set))
            {
                return set.Contains(address);
            }
            return false;
        }
    }

    /// <summary>
    /// Main token info loader with caching and retry logic.
    /// </summary>
    public class TokenInfoLoader : IDisposable
    {
        private readonly HttpClient _httpClient;
        private readonly ConcurrentDictionary<string, CachedTokenInfo> _cache;
        private readonly SemaphoreSlim _rateLimitSemaphore;
        private readonly int _rateLimitTokensPerSecond;

        private class CachedTokenInfo
        {
            public TokenInfo Data { get; set; }
            public DateTime ExpiresAt { get; set; }
            public bool IsExpired => DateTime.UtcNow > ExpiresAt;
        }

        public event Action<string, string> OnCacheMiss;
        public event Action<string, string, Exception> OnError;

        public TokenInfoLoader(
            HttpClient httpClient = null,
            int cacheTtlMinutes = 60,
            int rateLimitTokensPerSecond = 10)
        {
            _httpClient = httpClient ?? TokenInfoLoaderConfig.DefaultHttpClient;
            _cache = new ConcurrentDictionary<string, CachedTokenInfo>();
            _rateLimitSemaphore = new SemaphoreSlim(rateLimitTokensPerSecond);
            _rateLimitTokensPerSecond = rateLimitTokensPerSecond;

            // Initialize blacklists
            TokenBlacklist.Initialize();
        }

        /// <summary>
        /// Loads token info with automatic caching and retry.
        /// </summary>
        public async Task<TokenInfo> LoadAsync(
            string contractAddress,
            string network = null,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(contractAddress))
                throw new ArgumentException("Contract address required", nameof(contractAddress));

            network ??= TokenInfoLoaderConfig.DefaultNetwork;
            var cacheKey = $"{network}:{contractAddress}";

            // Check cache first
            if (!_cache.TryGetValue(cacheKey, out var cached) || cached.IsExpired)
            {
                await _rateLimitSemaphore.WaitAsync(cancellationToken);
                try
                {
                    OnCacheMiss?.Invoke(network, contractAddress);
                    return await FetchFromApiAsync(contractAddress, network, cancellationToken);
                }
                finally
                {
                    _rateLimitSemaphore.Release();
                }
            }

            // Cache hit - but verify freshness
            if (!cached.IsExpired)
            {
                return cached.Data;
            }

            // Stale cache - refresh anyway
            await _rateLimitSemaphore.WaitAsync(cancellationToken);
            try
            {
                OnCacheMiss?.Invoke(network, contractAddress);
                var fresh = await FetchFromApiAsync(contractAddress, network, cancellationToken);
                cached.Data = fresh;
                cached.ExpiresAt = DateTime.UtcNow.AddMinutes(_cacheTtlMinutes / 2); // Refresh half TTL
                return fresh;
            }
            finally
            {
                _rateLimitSemaphore.Release();
            }
        }

        /// <summary>
        /// Fetches token info from Etherscan API.
        /// </summary>
        private async Task<TokenInfo> FetchFromApiAsync(
            string contractAddress,
            string network,
            CancellationToken cancellationToken)
        {
            var baseUrl = GetBaseUrl(network);
            var url = $"{baseUrl}/api?module=contract&action=getcontractdetails&address={Uri.EscapeDataString(contractAddress)}";

            if (!string.IsNullOrEmpty(TokenInfoLoaderConfig.DefaultHttpClient.BaseAddress))
            {
                // Allow override via config
            }

            int attempt = 0;
            while (attempt < TokenInfoLoaderConfig.MaxRetries)
            {
                try
                {
                    var response = await _httpClient.GetAsync(url, cancellationToken);
                    
                    if (!response.IsSuccessStatusCode)
                    {
                        if (attempt == 0)
                            OnError?.Invoke(network, contractAddress, new HttpRequestException($"API returned {response.StatusCode}"));

                        attempt++;
                        await Task.Delay(TokenInfoLoaderConfig.RetryDelay * attempt, cancellationToken);
                        continue;
                    }

                    var json = await response.Content.ReadAsStringAsync(cancellationToken);
                    if (string.IsNullOrEmpty(json))
                    {
                        OnError?.Invoke(network, contractAddress, new InvalidOperationException("Empty API response"));
                        attempt++;
                        continue;
                    }

                    return ParseResponse(json, network, contractAddress);
                }
                catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
                {
                    if (attempt == 0)
                        OnError?.Invoke(network, contractAddress, new HttpRequestException($"Request failed: {ex.Message}"));

                    attempt++;
                    await Task.Delay(TokenInfoLoaderConfig.RetryDelay * attempt, cancellationToken);
                }
            }

            // All retries exhausted - return minimal info
            return TokenInfo.CreateEmpty(contractAddress, network)
            {
                RiskLevel = TokenRiskLevel.Unknown,
                KnownIssues = { "API unreachable after multiple attempts" }
            };
        }

        private string GetBaseUrl(string network)
        {
            // Default to Etherscan for Ethereum
            return network.Equals("ethereum", StringComparison.OrdinalIgnoreCase) || 
                   network.StartsWith("eth") ? 
                   "https://api.etherscan.io/api" :
                   $"https://api.{network}.etherscan.io/api";
        }

        /// <summary>
        /// Parses the Etherscan API JSON response.
        /// </summary>
        private TokenInfo ParseResponse(string json, string network, string contractAddress)
        {
            var options = new JsonSerializerOptions 
            { 
                PropertyNameCaseInsensitive = true,
                Converters = { new JsonStringEnumConverter() }
            };

            try
            {
                var root = JsonSerializer.Deserialize<ApiRoot>(json, options);
                
                if (root?.Result == null)
                    return TokenInfo.CreateEmpty(contractAddress, network)
                    {
                        RiskLevel = TokenRiskLevel.Unknown,
                        KnownIssues = { "API returned no result" }
                    };

                var data = root.Result;

                // Build token info
                var info = new TokenInfo
                {
                    NetworkName = network,
                    ContractAddress = contractAddress,
                    Name = data.Name ?? string.Empty,
                    Symbol = data.Symbol ?? string.Empty,
                    Decimals = data.Decimals ?? 18,
                    IsVerified = !string.IsNullOrEmpty(data.SourceCode),
                    VerifiedAt = data.VerifiedSourceDate != null 
                        ? DateTime.Parse(data.VerifiedSourceDate) : DateTime.UtcNow,
                    SourceCode = data.SourceCode,
                    CompilerVersion = data.CompilerVersion,
                };

                // Determine risk level
                info.RiskLevel = AssessRiskLevel(info);

                // Check for known issues
                if (TokenBlacklist.IsBlacklisted(contractAddress, network))
                {
                    info.KnownIssues.Add("Contract in drainer blacklist");
                    info.RiskLevel = TokenRiskLevel.DrainerCandidate;
                }

                return info;
            }
            catch (JsonException ex)
            {
                OnError?.Invoke(network, contractAddress, new JsonException($"JSON parse failed: {ex.Message}"));
                return TokenInfo.CreateEmpty(contractAddress, network)
                {
                    RiskLevel = TokenRiskLevel.Unknown,
                    KnownIssues = { "Failed to parse API response" }
                };
            }
        }

        /// <summary>
        /// Assesses risk level based on collected metadata.
        /// </summary>
        private TokenRiskLevel AssessRiskLevel(TokenInfo info)
        {
            // Unknown if minimal data
            if (string.IsNullOrEmpty(info.Name) && string.IsNullOrEmpty(info.Symbol))
                return TokenRiskLevel.Unknown;

            // Verified contracts are generally safer
            if (info.IsVerified && !info.KnownIssues.Any())
                return TokenRiskLevel.Safe;

            // Check for suspicious patterns in source code
            var suspiciousPatterns = new[]
            {
                "transfer:require",          // Transfer restrictions
                "approve:require",           // Approval restrictions  
                "balanceOf:require",        // Balance checks before transfer
                "nonReentrant",             // Reentrancy guards (good, but indicates complexity)
                "delegatecall",             // Potential proxy pattern
            };

            if (info.SourceCode != null)
            {
                var sourceLower = info.SourceCode.ToLower();
                
                foreach (var pattern in suspiciousPatterns)
                {
                    if (sourceLower.Contains(pattern))
                        info.KnownIssues.Add($"Pattern detected: {pattern}");
                }

                // If multiple patterns found, increase suspicion
                if (info.KnownIssues.Count >= 3)
                    return TokenRiskLevel.Suspicious;
            }

            // Default to safe for verified contracts with minimal issues
            return info.IsVerified ? 
                   TokenRiskLevel.Safe : 
                   TokenRiskLevel.Unknown;
        }

        /// <summary>
        /// Clears the cache.
        /// </summary>
        public void ClearCache()
        {
            _cache.Clear();
        }

        /// <summary>
        /// Disposes resources.
        /// </summary>
        public void Dispose()
        {
            _httpClient?.Dispose();
            _rateLimitSemaphore.Dispose();
        }
    }

    // API Root wrapper for Etherscan response
    private class ApiRoot
    {
        [JsonPropertyName("result")]
        public ContractDetails Result { get; set; }
    }

    private class ContractDetails
    {
        [JsonPropertyName("name")]
        public string Name { get; set; }

        [JsonPropertyName("symbol")]
        public string Symbol { get; set; }

        [JsonPropertyName("decimals")]
        public int? Decimals { get; set; }

        [JsonPropertyName("sourceCode")]
        public string SourceCode { get; set; }

        [JsonPropertyName("verifiedSourceDate")]
        public string VerifiedSourceDate { get; set; }

        [JsonPropertyName("compilerVersion")]
        public string CompilerVersion { get; set; }
    }

    /// <summary>
    /// Demo/entry point for testing the loader.
    /// </summary>
    public class Program
    {
        private static async Task Main(string[] args)
        {
            Console.WriteLine("ApproveWarden Token Info Loader Demo");
            Console.WriteLine("====================================\n");

            // Create loader with custom config
            var loader = new TokenInfoLoader(
                cacheTtlMinutes: 15,
                rateLimitTokensPerSecond: 20
            );

            // Test cases
            var testCases = new[]
            {
                ("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "Ethereum Mainnet"),
                ("0xdAC17F958D2ee523a2206206994597C13D831ec7", "Ethereum Mainnet"),
                ("0x1f98431c8ad98523631ae4a59f267346ea31f984", "Ethereum Mainnet"),
            };

            foreach (var (address, network) in testCases)
            {
                Console.WriteLine($"Loading: {network} - {address.Substring(0, 10)}...");
                
                try
                {
                    var info = await loader.LoadAsync(address, network);
                    
                    // Print results
                    Console.WriteLine($"  Name:    {info.Name ?? "Unknown"}");
                    Console.WriteLine($"  Symbol:   {info.Symbol ?? "Unknown"}");
                    Console.WriteLine($"  Decimals: {info.Decimals}");
                    Console.WriteLine($"  Verified: {info.IsVerified}");
                    Console.WriteLine($"  Risk:     {info.RiskLevel}");
                    
                    if (info.KnownIssues.Count > 0)
                    {
                        Console.WriteLine("  Issues:");
                        foreach (var issue in info.KnownIssues)
                            Console.WriteLine($"    - {issue}");
                    }

                    Console.WriteLine();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  Error: {ex.Message}");
                    Console.WriteLine();
                }
            }

            // Cleanup
            loader.Dispose();
            Console.WriteLine("Demo complete. Loader disposed.");
        }
    }
}