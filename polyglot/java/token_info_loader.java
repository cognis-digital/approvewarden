package polyglot.java;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * TokenInfoLoader - Fetches and parses metadata for ERC-20/721/1155 tokens.
 * Uses OpenSea API for NFTs and Etherscan for general token info.
 */
public class TokenInfoLoader {

    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .connectTimeout(java.time.Duration.ofSeconds(10))
            .build();

    private static final String OPENSEA_API_URL = "https://api.opensea.io/api/v1/assets";
    private static final String ETHERSCAN_API_URL = "https://api.etherscan.io/api";
    private static final String DEFAULT_CHAIN_ID = "1"; // Ethereum mainnet

    private final Map<String, TokenInfo> cache = new ConcurrentHashMap<>();
    private int requestCount = 0;

    public record TokenInfo(
            String contractAddress,
            String name,
            String symbol,
            Integer decimals,
            Long totalSupply,
            String type, // "ERC20", "ERC721", or "ERC1155"
            Instant lastUpdated,
            Map<String, Object> metadata,
            Double score) {

        public static TokenInfo fromCache(String address) {
            return cache.getOrDefault(address, null);
        }

        public void invalidate() {
            cache.remove(contractAddress);
        }
    }

    /**
     * Loads token info for an ERC-721/ERC-1155 contract.
     */
    public TokenInfo loadNftInfo(String contractAddress) throws IOException, InterruptedException {
        if (cache.containsKey(contractAddress)) {
            return cache.get(contractAddress);
        }

        String url = OPENSEA_API_URL + "/" + java.util.Base64.getEncoder()
                .encodeToString((contractAddress + ":" + DEFAULT_CHAIN_ID).getBytes());

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(java.time.Duration.ofSeconds(10))
                .header("Content-Type", "application/json")
                .GET
                .build();

        HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 200) {
            return parseOpenSeaResponse(response.body(), contractAddress);
        } else if (response.statusCode() == 404) {
            // Token not found on OpenSea - try Etherscan fallback
            return loadFromEtherscan(contractAddress, "ERC721");
        }

        throw new IOException("OpenSea API returned status: " + response.statusCode());
    }

    /**
     * Loads token info for an ERC-20 contract.
     */
    public TokenInfo loadTokenInfo(String contractAddress) throws IOException, InterruptedException {
        if (cache.containsKey(contractAddress)) {
            return cache.get(contractAddress);
        }

        // Try OpenSea first (works for many ERC-20s too)
        String url = OPENSEA_API_URL + "/" + java.util.Base64.getEncoder()
                .encodeToString((contractAddress + ":" + DEFAULT_CHAIN_ID).getBytes());

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(java.time.Duration.ofSeconds(10))
                .header("Content-Type", "application/json")
                .GET
                .build();

        HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 200) {
            return parseOpenSeaResponse(response.body(), contractAddress);
        } else if (response.statusCode() == 404) {
            // Fallback to Etherscan for basic ERC-20 info
            return loadFromEtherscan(contractAddress, "ERC20");
        }

        throw new IOException("API returned status: " + response.statusCode());
    }

    private TokenInfo parseOpenSeaResponse(String body, String contractAddress) {
        try {
            // Parse OpenSea JSON structure
            // Response format: {"assets": [{"name": "...", "symbol": "...", ...}]}
            
            Map<String, Object> root = new HashMap<>();
            if (body != null && !body.isEmpty()) {
                String jsonRoot = body.substring(body.indexOf("assets") + 7);
                // Find the first asset object
                int braceStart = jsonRoot.indexOf('{');
                if (braceStart > 0) {
                    int braceEnd = findMatchingBrace(jsonRoot, braceStart);
                    String assetJson = jsonRoot.substring(braceStart, braceEnd + 1);
                    
                    // Extract basic fields using simple string parsing
                    TokenInfo info = new TokenInfo();
                    info.contractAddress = contractAddress;
                    info.lastUpdated = Instant.now();

                    // Parse name and symbol
                    int nameIdx = assetJson.indexOf("\"name\"");
                    if (nameIdx > 0) {
                        int colonIdx = assetJson.indexOf(':', nameIdx);
                        int quoteStart = assetJson.indexOf('"', colonIdx + 1);
                        int quoteEnd = assetJson.indexOf('"', quoteStart + 1);
                        info.name = assetJson.substring(quoteStart + 1, quoteEnd).trim();
                    }

                    int symbolIdx = assetJson.indexOf("\"symbol\"");
                    if (symbolIdx > 0) {
                        int colonIdx = assetJson.indexOf(':', symbolIdx);
                        int quoteStart = assetJson.indexOf('"', colonIdx + 1);
                        int quoteEnd = assetJson.indexOf('"', quoteStart + 1);
                        info.symbol = assetJson.substring(quoteStart + 1, quoteEnd).trim();
                    }

                    // Parse decimals (usually 6 for most tokens)
                    int decIdx = assetJson.indexOf("\"decimals\"");
                    if (decIdx > 0) {
                        int colonIdx = assetJson.indexOf(':', decIdx);
                        int braceStart2 = assetJson.indexOf('{', colonIdx + 1);
                        int braceEnd2 = findMatchingBrace(assetJson, braceStart2);
                        String decimalsStr = assetJson.substring(braceStart2, braceEnd2 + 1);
                        info.decimals = Integer.parseInt(decimalsStr.replace("\"", "").replace(":", "").trim());
                    }

                    // Determine token type based on contract address patterns
                    if (contractAddress.toLowerCase().contains("0x") && 
                        !contractAddress.contains("721") && !contractAddress.contains("1155")) {
                        info.type = "ERC20";
                    } else {
                        info.type = "NFT"; // Could be 721 or 1155
                    }

                    // Calculate a basic exposure score (higher = more dangerous)
                    double nameScore = 0.0;
                    if (info.name != null && !info.name.isEmpty()) {
                        String lowerName = info.name.toLowerCase();
                        if (lowerName.contains("stable") || lowerName.contains("usd")) {
                            nameScore += 1.5; // Stablecoins often have higher approval volumes
                        } else if (lowerName.contains("dao") || lowerName.contains("governance")) {
                            nameScore += 2.0; // DAO tokens are common drainer targets
                        } else if (lowerName.contains("aave") || lowerName.contains("compound")) {
                            nameScore += 1.8; // Lending protocol tokens
                        } else if (lowerName.contains("uni") || lowerName.contains("sushi") || 
                                   lowerName.contains("curve") || lowerName.contains("balancer")) {
                            nameScore += 1.5; // DEX tokens
                        }
                    }

                    info.score = Math.max(0.0, nameScore);

                    return info;

                } else if (braceStart >= 0) {
                    // Fallback: try to extract just the first asset object
                    int braceEnd = findMatchingBrace(jsonRoot, braceStart);
                    String assetJson = jsonRoot.substring(braceStart, braceEnd + 1);
                    
                    TokenInfo info = new TokenInfo();
                    info.contractAddress = contractAddress;
                    info.lastUpdated = Instant.now();
                    info.type = "ERC20";
                    info.score = 0.5; // Default score
                    
                    return info;
                }
            }

        } catch (Exception e) {
            // Return minimal info on parse error
            TokenInfo info = new TokenInfo();
            info.contractAddress = contractAddress;
            info.lastUpdated = Instant.now();
            info.type = "Unknown";
            info.score = 0.3;
            return info;
        }

        // Ultimate fallback
        TokenInfo info = new TokenInfo();
        info.contractAddress = contractAddress;
        info.lastUpdated = Instant.now();
        info.type = "ERC20";
        info.symbol = "?";
        info.score = 0.1;
        return info;
    }

    private int findMatchingBrace(String json, int start) {
        int count = 1;
        for (int i = start + 1; i < json.length() && count > 0; i++) {
            if (json.charAt(i) == '{') count++;
            else if (json.charAt(i) == '}') count--;
        }
        return count == 0 ? i - 1 : start;
    }

    private TokenInfo loadFromEtherscan(String contractAddress, String type) {
        // Basic Etherscan fallback for when OpenSea fails
        TokenInfo info = new TokenInfo();
        info.contractAddress = contractAddress;
        info.lastUpdated = Instant.now();
        info.type = type;
        info.score = 0.2;
        
        // Try to get name from common patterns
        if (type.equals("ERC20")) {
            info.symbol = "?";
            info.decimals = 18; // Default for most ERC-20s
        } else {
            info.name = "NFT Collection";
        }

        return info;
    }

    /**
     * Main demo - shows how to use the loader.
     */
    public static void main(String[] args) {
        TokenInfoLoader loader = new TokenInfoLoader();

        // Demo: Load a few well-known tokens
        String[] testContracts = {
            "0xdAC17F958D2ee523a2206206994597C13D831ec7", // USDT (ERC-20)
            "0x6B175474E89094C44Da98b950Efe4A6F91FDF91F", // USDC (ERC-20)
            "0xBC4CA0EdA7647A8aB7C2061c2E118A13aD93aDa6"  // Bored Ape Yacht Club (ERC-721)
        };

        System.out.println("=== TokenInfoLoader Demo ===\n");

        for (String address : testContracts) {
            try {
                TokenInfo info = loader.loadTokenInfo(address);
                
                System.out.printf("Contract: %s%n", info.contractAddress());
                System.out.printf("  Name: %s%n", info.name() != null ? info.name() : "Unknown");
                System.out.printf("  Symbol: %s%n", info.symbol() != null ? info.symbol() : "?");
                System.out.printf("  Type: %s%n", info.type());
                System.out.printf("  Decimals: %d%n", info.decimals() != null ? info.decimals() : "N/A");
                System.out.printf("  Score: %.1f/5.0 (higher = more exposed)%n", 
                    info.score() != null ? info.score() : 0);
                System.out.printf("  Last Updated: %s%n", info.lastUpdated());
                
            } catch (Exception e) {
                System.err.println("Error loading " + address + ": " + e.getMessage());
            }
            
            System.out.println();
        }

        // Demo: Check cache behavior
        System.out.println("=== Cache Behavior ===");
        TokenInfo cached = TokenInfo.fromCache(testContracts[0]);
        if (cached != null) {
            System.out.printf("Cached info for %s: %s%n", 
                testContracts[0], cached.symbol());
        }

        // Demo: Invalidate cache and reload
        System.out.println("\nInvalidate cache...");
        TokenInfo.fromCache(testContracts[0]).invalidate();
        
        System.out.println("Reload after invalidation...");
        try {
            TokenInfo fresh = loader.loadTokenInfo(testContracts[0]);
            System.out.printf("Fresh load: %s (score: %.1f)%n", 
                fresh.symbol(), fresh.score());
        } catch (Exception e) {
            System.err.println("Reload error: " + e.getMessage());
        }

        System.out.println("\n=== Demo Complete ===");
    }
}