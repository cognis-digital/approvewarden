import { ethers } from 'ethers';

// ============================================================================
// CONFIGURATION & CONSTANTS
// ============================================================================

const DEFAULT_CONFIG = {
  etherscanBaseUrl: 'https://api.etherscan.io',
  coingeckoBaseUrl: 'https://api.coingecko.com/api/v3',
  defaultEtherscanApiKey: '',
  defaultCoingeckoApiKey: '',
  cacheTTL: 5 * 60 * 1000, // 5 minutes
  maxRetries: 3,
  retryDelayMs: 200,
};

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

export type TokenType = 'ERC20' | 'ERC721' | 'ERC1155';

interface BaseTokenInfo {
  chainId: number;
  address: string;
  name?: string;
  symbol?: string;
  decimals?: number;
  type: TokenType;
}

export interface ERC20Info extends BaseTokenInfo {
  type: 'ERC20';
  totalSupply?: string;
  isMintable?: boolean;
  isBurnable?: boolean;
  isPausable?: boolean;
  isBlacklistable?: boolean;
}

export interface ERC721Info extends BaseTokenInfo {
  type: 'ERC721';
  totalSupply?: string; // Total minted tokens
  name?: string;
  symbol?: string;
}

export interface ERC1155Info extends BaseTokenInfo {
  type: 'ERC1155';
  isIndestructible?: boolean;
  isPausable?: boolean;
  isBurnable?: boolean;
  isMintable?: boolean;
  isBlacklistable?: boolean;
}

export interface TokenMetadata {
  logoUrl?: string;
  website?: string;
  twitter?: string;
  telegram?: string;
  coingeckoId?: string;
}

export type FullTokenInfo = ERC20Info | ERC721Info | ERC1155Info & {
  metadata: TokenMetadata;
};

interface LoadingOptions {
  etherscanApiKey?: string;
  coingeckoApiKey?: string;
  chainId?: number;
  cacheEnabled?: boolean;
}

export interface LoadingResult<T extends BaseTokenInfo> {
  success: boolean;
  data: T | null;
  error: string | null;
  source: 'cache' | 'etherscan' | 'coingecko' | 'rpc' | 'fallback';
  timestamp: number;
}

// ============================================================================
// CACHING LAYER
// ============================================================================

class TokenCache {
  private cache: Map<string, FullTokenInfo> = new Map();
  private ttlMs: number;

  constructor(ttlMs: number = DEFAULT_CONFIG.cacheTTL) {
    this.ttlMs = ttlMs;
  }

  get(key: string): FullTokenInfo | undefined {
    const entry = this.cache.get(key);
    if (!entry) return undefined;

    const now = Date.now();
    if (now - entry.timestamp > this.ttlMs) {
      this.cache.delete(key);
      return undefined;
    }

    return entry.data;
  }

  set(key: string, data: FullTokenInfo): void {
    this.cache.set(key, {
      data,
      timestamp: Date.now(),
    });
  }

  clear(): void {
    this.cache.clear();
  }

  size(): number {
    return this.cache.size;
  }
}

const cache = new TokenCache(DEFAULT_CONFIG.cacheTTL);

// ============================================================================
// TOKEN INFO LOADER IMPLEMENTATION
// ============================================================================

export class TokenInfoLoader {
  private config: Required<LoadingOptions>;
  private cache: TokenCache;

  constructor(options?: LoadingOptions) {
    this.config = {
      etherscanApiKey: options?.etherscanApiKey || DEFAULT_CONFIG.defaultEtherscanApiKey,
      coingeckoApiKey: options?.coingeckoApiKey || DEFAULT_CONFIG.defaultCoingeckoApiKey,
      chainId: options?.chainId || 1, // Ethereum mainnet default
      cacheEnabled: options?.cacheEnabled ?? true,
    };

    this.cache = this.config.cacheEnabled ? new TokenCache() : new TokenCache(0);
  }

  private getEtherscanBaseUrl(chainId: number): string {
    const chainMap: Record<number, string> = {
      1: 'https://api.etherscan.io',
      3: 'https://api.ropsten.etherscan.io',
      5: 'https://api.goerli.etherscan.io',
      42: 'https://api.kovan.etherscan.io',
    };

    return chainMap[chainId] || DEFAULT_CONFIG.etherscanBaseUrl;
  }

  private getCoingeckoId(chainId: number): string | undefined {
    const coingeckoChainMap: Record<number, string> = {
      1: 'ethereum',
      3: 'ropsten',
      5: 'goerli',
      42: 'kovan',
      8453: 'base',
      84532: 'base-sepolia',
    };

    return coingeckoChainMap[chainId];
  }

  private async fetchWithRetry<T>(
    url: string,
    options: RequestInit = {},
    retries = DEFAULT_CONFIG.maxRetries
  ): Promise<Response> {
    for (let attempt = 0; attempt < retries; attempt++) {
      try {
        const response = await fetch(url, options);

        if (response.ok) return response;

        // Handle rate limiting
        if (response.status === 429) {
          const retryAfter = response.headers.get('Retry-After');
          const delayMs = retryAfter ? parseInt(retryAfter, 10) * 1000 : DEFAULT_CONFIG.retryDelayMs * (attempt + 1);

          await new Promise(resolve => setTimeout(resolve, Math.min(delayMs, 60000)));
        }

        return response;
      } catch (error: unknown) {
        if (attempt === retries - 1) throw error;
        await new Promise(resolve => setTimeout(resolve, DEFAULT_CONFIG.retryDelayMs * (attempt + 1)));
      }
    }

    throw new Error(`Max retries exceeded for ${url}`);
  }

  private async fetchFromEtherscan(
    address: string,
    chainId: number
  ): Promise<{ name?: string; symbol?: string; decimals?: number; type: TokenType }> {
    const baseUrl = this.getEtherscanBaseUrl(chainId);
    const apiKey = this.config.etherscanApiKey || DEFAULT_CONFIG.defaultEtherscanApiKey;

    if (!apiKey) {
      return { type: 'ERC20' as TokenType }; // Fallback without API key
    }

    try {
      const url = `${baseUrl}/api?module=token&action=tokentx&address=${address}&chainid=${chainId}`;
      const response = await this.fetchWithRetry(url);

      if (!response.ok) {
        return { type: 'ERC20' as TokenType };
      }

      const data = await response.json();
      const tokens = Array.isArray(data.result) ? data.result : [];

      if (tokens.length === 0) {
        return { type: 'ERC20' as TokenType };
      }

      const token = tokens[0];
      let type: TokenType;

      // Detect token type from contract code hash or name pattern
      if (token.contractAddress?.toLowerCase() === address.toLowerCase()) {
        // This is the actual token, not a wrapper
        if (address.toLowerCase().includes('721') || address.toLowerCase().includes('1155')) {
          type = 'ERC721' as TokenType;
        } else if (address.toLowerCase().includes('1155')) {
          type = 'ERC1155' as TokenType;
        } else {
          type = 'ERC20' as TokenType;
        }
      } else {
        // Wrapper token - check for known patterns
        if (address.toLowerCase().includes('721') || address.toLowerCase().includes('1155')) {
          type = 'ERC721' as TokenType;
        } else {
          type = 'ERC20' as TokenType;
        }
      }

      return {
        name: token.name,
        symbol: token.symbol,
        decimals: Number(token.decimals),
        type,
      };
    } catch (error) {
      console.warn(`Etherscan fetch failed for ${address}:`, error);
      return { type: 'ERC20' as TokenType };
    }
  }

  private async fetchFromCoingecko(
    address: string,
    chainId: number
  ): Promise<{ name?: string; symbol?: string; decimals?: number }> {
    const coingeckoChain = this.getCoingeckoId(chainId);

    if (!coingeckoChain) {
      return {};
    }

    try {
      const url = `${DEFAULT_CONFIG.coingeckoBaseUrl}/simple/coins?vs_currencies=usd&include_24hr_vol=true&include_market_cap=true&filter.by_coingecko_id=${coingeckoChain}`;
      
      // Search by contract address - need to use different endpoint
      const searchUrl = `${DEFAULT_CONFIG.coingeckoBaseUrl}/search?q=${address}&order=market_cap_desc&per_page=1&page=0&sparkline=false`;

      const response = await this.fetchWithRetry(searchUrl);
      if (!response.ok) return {};

      const data = await response.json();
      
      // Coingecko search returns objects with id, symbol, name, image, etc.
      // But we need to match by contract address which requires different approach
      
      // For now, fall back to using the chain's default coin info
      return {
        name: coingeckoChain.charAt(0).toUpperCase() + coingeckoChain.slice(1),
        symbol: coingeckoChain.toUpperCase(),
        decimals: 18, // Ethereum standard
      };
    } catch (error) {
      console.warn(`Coingecko fetch failed for ${address}:`, error);
      return {};
    }
  }

  private async detectTokenType(
    address: string,
    chainId: number
  ): Promise<TokenType> {
    // Quick heuristic checks before expensive API calls
    
    // Check if it's a known ERC721/ERC1155 pattern
    const lowerAddr = address.toLowerCase();
    
    if (lowerAddr.includes('0x721') || lowerAddr.includes('0x1155')) {
      return 'ERC721' as TokenType;
    }

    // Check contract code hash for common patterns
    try {
      const provider = new ethers.JsonRpcProvider(chainId);
      
      if (provider) {
        const code = await provider.getCode(address);
        
        // ERC721/ERC1155 contracts typically have specific bytecode patterns
        // These are simplified checks - production would need more robust detection
        
        if (code.length > 100 && lowerAddr.includes('721')) {
          return 'ERC721' as TokenType;
        }

        if (code.length > 500 && lowerAddr.includes('1155')) {
          return 'ERC1155' as TokenType;
        }
      }
    } catch (error) {
      console.warn(`RPC code fetch failed:`, error);
    }

    // Default to ERC20 for unknown contracts
    return 'ERC20' as TokenType;
  }

  private async enrichWithMetadata(
    address: string,
    chainId: number,
    baseInfo: { name?: string; symbol?: string; decimals?: number; type: TokenType }
  ): Promise<FullTokenInfo> {
    const metadata: TokenMetadata = {};

    // Try to get logo from Etherscan
    try {
      const baseUrl = this.getEtherscanBaseUrl(chainId);
      const apiKey = this.config.etherscanApiKey || DEFAULT_CONFIG.defaultEtherscanApiKey;

      if (apiKey) {
        const url = `${baseUrl}/api?module=token&action=gettokenlogo&address=${address}&chainid=${chainId}`;
        const response = await this.fetchWithRetry(url);

        if (response.ok) {
          const data = await response.json();
          if (data.result?.length > 0 && data.result[0].image !== 'https://static.ether-scan.com/images/eth.png') {
            metadata.logoUrl = data.result[0].image;
          }
        }
      }

      // Try Coingecko for additional metadata
      try {
        const coingeckoData = await this.fetchFromCoingecko(address, chainId);
        
        if (coingeckoData.name) {
          metadata.website = `https://www.coingecko.com/en/coins/${coingeckoData.symbol?.toLowerCase()}`;
        }

        // Check for social links in contract name or common patterns
        const lowerName = baseInfo.name?.toLowerCase() || '';
        
        if (lowerName.includes('twitter') || lowerName.includes('x')) {
          metadata.twitter = `https://twitter.com/${lowerName.replace('@', '').replace('/', '')}`;
        }

        if (lowerName.includes('telegram') || lowerName.includes('t.me')) {
          const telegramMatch = lowerName.match(/(t\.me|telegram\.org)\/([^/\s]+)/);
          if (telegramMatch) {
            metadata.telegram = `https://${telegramMatch[2]}`;
          }
        }

      } catch (error) {
        // Coingecko error is non-fatal
      }

    } catch (error) {
      console.warn(`Metadata enrichment failed:`, error);
    }

    return { ...baseInfo, metadata };
  }

  private async fetchContractCode(
    address: string,
    chainId: number
  ): Promise<string> {
    const provider = new ethers.JsonRpcProvider(chainId);
    
    try {
      if (provider) {
        return await provider.getCode(address);
      }
    } catch (error) {
      console.warn(`RPC code fetch failed:`, error);
    }

    return '0x';
  }

  private async analyzeContractCode(
    address: string,
    chainId: number,
    baseInfo: { name?: string; symbol?: string; decimals?: number; type: TokenType }
  ): Promise<Partial<ERC20Info | ERC721Info | ERC1155Info>> {
    const code = await this.fetchContractCode(address, chainId);

    if (code === '0x') {
      return {}; // Contract doesn't exist or not deployed yet
    }

    // Basic heuristic analysis of contract code
    const lowerCode = code.toLowerCase();
    const baseAddr = address.toLowerCase();

    let flags: Partial<ERC20Info | ERC721Info | ERC1155Info> = {};

    // Check for common dangerous patterns in ERC20 contracts
    if (baseInfo.type === 'ERC20') {
      const dangerousPatterns: Record<string, boolean> = {
        isMintable: lowerCode.includes('mint') || lowerCode.includes('setTotalSupply'),
        isBurnable: lowerCode.includes('burn') && !lowerCode.includes('safeburn'),
        isPausable: lowerCode.includes('pause') || lowerCode.includes('paused'),
        isBlacklistable: lowerCode.includes('blacklist') || lowerCode.includes('whitelist'),
      };

      flags = { ...flags, ...dangerousPatterns };
    }

    // Check for ERC721/ERC1155 specific patterns
    if (baseInfo.type === 'ERC721' || baseInfo.type === 'ERC1155') {
      const nftPatterns: Record<string, boolean> = {
        isIndestructible: lowerCode.includes('indestructible'),
        isPausable: lowerCode.includes('pause'),
        isBurnable: lowerCode.includes('burn'),
        isMintable: lowerCode.includes('mint') || lowerCode.includes('setTotalSupply'),
      };

      flags = { ...flags, ...nftPatterns };
    }

    return flags;
  }

  private async loadFromCache(
    address: string,
    chainId: number
  ): Promise<LoadingResult<Full