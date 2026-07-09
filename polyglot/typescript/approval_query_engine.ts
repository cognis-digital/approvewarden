import { ethers } from 'ethers';

// ============================================================================
// TYPES & CONSTANTS
// ============================================================================

export type Address = string;
export type ChainId = number;

const INFINITE_ALLOWANCE = ethers.constants.MaxUint256.toString();

// Dangerous approval patterns
export interface DangerPattern {
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

const DANGER_PATTERNS: DangerPattern[] = [
  {
    name: 'INFINITE_ALLOWANCE',
    description: 'Unlimited token transfer allowance (classic drainer)',
    severity: 'critical',
  },
  {
    name: 'SELF_APPROVAL',
    description: 'Contract approved to spend its own tokens',
    severity: 'high',
  },
  {
    name: 'UNKNOWN_CONTRACT',
    description: 'Approval granted to unverified contract address',
    severity: 'medium',
  },
];

// ============================================================================
// DATA MODELS
// ============================================================================

export interface TokenInfo {
  address: Address;
  symbol?: string;
  name?: string;
  decimals: number;
}

export interface ApprovalRecord {
  tokenAddress: Address;
  spenderAddress: Address;
  amount: ethers.BigNumberish;
  isApprovedForAll: boolean;
  tokenType: 'ERC20' | 'ERC721' | 'ERC1155';
}

export interface WalletScanResult {
  address: Address;
  totalApprovals: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  dangerPatternsFound: string[];
  totalScore: number;
  approvals: ApprovalRecord[];
}

export interface RevokeTransaction {
  tokenAddress: Address;
  spenderAddress: Address;
  amount?: ethers.BigNumberish;
  isApprovedForAll: boolean;
  method: 'setApprovalForAll' | 'approve';
  params: any[];
  estimatedGas: number;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function normalizeAddress(addr: string): Address {
  let normalized = addr.toLowerCase();
  if (normalized.length === 42) {
    normalized = ethers.utils.removePrefix(normalized, '0x');
  }
  return normalized;
}

function isMaxUint256(amount: ethers.BigNumberish): boolean {
  const maxStr = INFINITE_ALLOWANCE;
  if (typeof amount === 'string') {
    return amount.toLowerCase() === maxStr.toLowerCase();
  }
  return amount.eq(ethers.constants.MaxUint256);
}

function calculateScore(severity: string): number {
  const scores: Record<string, number> = {
    critical: 100,
    high: 50,
    medium: 25,
    low: 10,
  };
  return scores[severity] || 0;
}

// ============================================================================
// TOKEN SCANNER (ERC-20)
// ============================================================================

export class ERC20Scanner {
  private provider: ethers.JsonRpcProvider;
  private cache = new Map<string, TokenInfo>();

  constructor(provider: ethers.JsonRpcProvider) {
    this.provider = provider;
  }

  async getOrCreateToken(address: Address): Promise<TokenInfo> {
    const key = normalizeAddress(address);
    if (this.cache.has(key)) {
      return this.cache.get(key)!;
    }

    // Fetch token metadata from Etherscan API
    try {
      const response = await fetch(
        `https://api.etherscan.io/api?module=contract&action=gettokeninfo&address=${key}&chainid=1`
      );
      const data = await response.json();
      
      if (data.result && data.result.length > 0) {
        const token: TokenInfo = {
          address: key,
          symbol: data.result[0].symbol || 'UNKNOWN',
          name: data.result[0].name || 'Unknown Token',
          decimals: parseInt(data.result[0].decimals || '18'),
        };
        this.cache.set(key, token);
        return token;
      }
    } catch (e) {
      // Fallback to basic info if API fails
    }

    const fallback: TokenInfo = {
      address: key,
      symbol: 'UNKNOWN',
      name: 'Unknown Token',
      decimals: 18,
    };
    this.cache.set(key, fallback);
    return fallback;
  }

  async getApprovals(address: Address): Promise<ApprovalRecord[]> {
    const token = await this.getOrCreateToken(address);
    
    // Get spender list from Etherscan
    try {
      const response = await fetch(
        `https://api.etherscan.io/api?module=account&action=tokentx&address=${address}&page=1&page-size=1000&chainid=1`
      );
      const data = await response.json();

      if (data.result) {
        // Filter for approval transactions only
        return data.result
          .filter((tx: any) => tx.type === 'approval')
          .map((tx: any) => ({
            tokenAddress: address,
            spenderAddress: normalizeAddress(tx.to),
            amount: ethers.BigNumber.from(tx.value || '0'),
            isApprovedForAll: false, // ERC-20 doesn't have this concept
            tokenType: 'ERC20',
          }));
      }
    } catch (e) {
      console.warn('Failed to fetch approvals:', e);
    }

    return [];
  }

  async getAllowances(address: Address): Promise<ApprovalRecord[]> {
    const token = await this.getOrCreateToken(address);
    
    try {
      // Get allowance list from Etherscan
      const response = await fetch(
        `https://api.etherscan.io/api?module=account&action=tokentx&address=${address}&page=1&page-size=1000&chainid=1`
      );
      const data = await response.json();

      if (data.result) {
        // Filter for allowance transactions
        return data.result
          .filter((tx: any) => tx.type === 'allowance')
          .map((tx: any) => ({
            tokenAddress: address,
            spenderAddress: normalizeAddress(tx.to),
            amount: ethers.BigNumber.from(tx.value || '0'),
            isApprovedForAll: false,
            tokenType: 'ERC20',
          }));
      }
    } catch (e) {
      console.warn('Failed to fetch allowances:', e);
    }

    return [];
  }

  async getAllowance(owner: Address, spender: Address): Promise<ethers.BigNumber> {
    const token = await this.getOrCreateToken(address);
    
    try {
      // Use multicall for efficiency if scanning multiple tokens
      const response = await fetch(
        `https://api.etherscan.io/api?module=account&action=tokentx&owner=${owner}&spender=${spender}&page=1&page-size=100&chainid=1`
      );
      const data = await response.json();

      if (data.result) {
        // Find the latest allowance transaction
        return ethers.BigNumber.from(data.result[0]?.value || '0');
      }
    } catch (e) {
      console.warn('Failed to fetch allowance:', e);
    }

    return ethers.BigNumber.from(0);
  }
}

// ============================================================================
// TOKEN SCANNER (ERC-721 / ERC-1155)
// ============================================================================

export class NFTScanner {
  private provider: ethers.JsonRpcProvider;
  private cache = new Map<string, TokenInfo>();

  constructor(provider: ethers.JsonRpcProvider) {
    this.provider = provider;
  }

  async getOrCreateNFT(address: Address): Promise<TokenInfo> {
    const key = normalizeAddress(address);
    
    if (this.cache.has(key)) {
      return this.cache.get(key)!;
    }

    try {
      // Check if it's ERC-721 or ERC-1155 using Etherscan API
      const response = await fetch(
        `https://api.etherscan.io/api?module=contract&action=getabi&address=${key}&chainid=1`
      );
      const data = await response.json();

      if (data.result && data.result.includes('setApprovalForAll')) {
        // Likely ERC-721 or ERC-1155
        this.cache.set(key, {
          address: key,
          symbol: 'UNKNOWN',
          name: 'Unknown NFT',
          decimals: 0,
        });
        return this.cache.get(key)!;
      }
    } catch (e) {
      console.warn('Failed to fetch NFT info:', e);
    }

    const fallback: TokenInfo = {
      address: key,
      symbol: 'UNKNOWN',
      name: 'Unknown NFT',
      decimals: 0,
    };
    this.cache.set(key, fallback);
    return fallback;
  }

  async getApprovedForAll(address: Address): Promise<ApprovalRecord[]> {
    const token = await this.getOrCreateNFT(address);
    
    try {
      // Get approved for all list from Etherscan
      const response = await fetch(
        `https://api.etherscan.io/api?module=account&action=tokentx&address=${address}&page=1&page-size=1000&chainid=1`
      );
      const data = await response.json();

      if (data.result) {
        // Filter for ApprovedForAll transactions
        return data.result
          .filter((tx: any) => tx.type === 'approvedforall')
          .map((tx: any) => ({
            tokenAddress: address,
            spenderAddress: normalizeAddress(tx.to),
            amount: ethers.BigNumber.from(tx.value || '0'),
            isApprovedForAll: true,
            tokenType: 'ERC721', // Default to ERC-721; can be refined later
          }));
      }
    } catch (e) {
      console.warn('Failed to fetch ApprovedForAll:', e);
    }

    return [];
  }

  async getApproved(address: Address, tokenId: string): Promise<Address | null> {
    try {
      const response = await fetch(
        `https://api.etherscan.io/api?module=contract&action=getnftapproved&address=${normalizeAddress(address)}&tokenid=${tokenId}&chainid=1`
      );
      const data = await response.json();

      if (data.result) {
        return normalizeAddress(data.result[0]?.owner || null);
      }
    } catch (e) {
      console.warn('Failed to fetch NFT approval:', e);
    }

    return null;
  }
}

// ============================================================================
// DANGER PATTERN DETECTOR
// ============================================================================

export class DangerDetector {
  private patterns = DANGER_PATTERNS;

  detectPatterns(approvals: ApprovalRecord[]): string[] {
    const found: string[] = [];

    for (const approval of approvals) {
      // Check infinite allowance
      if (isMaxUint256(approval.amount)) {
        found.push(DANGER_PATTERNS[0].name);
      }

      // Check self-approval
      if (approval.spenderAddress.toLowerCase() === approval.tokenAddress.toLowerCase()) {
        found.push(DANGER_PATTERNS[1].name);
      }

      // Check unknown contract (basic heuristic)
      const isLikelyContract = ethers.utils.isAddress(approval.spenderAddress);
      if (!isLikelyContract && !approval.isApprovedForAll) {
        found.push(DANGER_PATTERNS[2].name);
      }
    }

    // Remove duplicates while preserving order
    return [...new Set(found)];
  }

  getSeverityScore(severity: string): number {
    const scores: Record<string, number> = {
      critical: 100,
      high: 50,
      medium: 25,
      low: 10,
    };
    return scores[severity] || 0;
  }

  calculateTotalScore(approvals: ApprovalRecord[]): number {
    let total = 0;
    
    for (const approval of approvals) {
      if (isMaxUint256(approval.amount)) {
        total += this.getSeverityScore('critical');
      } else if (approval.isApprovedForAll) {
        total += this.getSeverityScore('high');
      }
    }

    return Math.min(total, 1000); // Cap at 1000
  }
}

// ============================================================================
// TRANSACTION BUILDER FOR REVOKES
// ============================================================================

export class RevokeBuilder {
  private provider: ethers.JsonRpcProvider;
  private signer?: ethers.Signer;

  constructor(provider: ethers.JsonRpcProvider, signer?: ethers.Signer) {
    this.provider = provider;
    this.signer = signer;
  }

  setSigner(signer: ethers.Signer): void {
    this.signer = signer;
  }

  async buildERC20Revoke(
    tokenAddress: Address,
    spenderAddress: Address,
    amount?: ethers.BigNumberish,
    isApprovedForAll: boolean = false
  ): Promise<RevokeTransaction> {
    const method = isApprovedForAll 
      ? 'setApprovalForAll' 
      : 'approve';

    let params: any[];
    
    if (isApprovedForAll) {
      // setApprovalForAll(spender, approved)
      params = [normalizeAddress(spenderAddress), false];
    } else {
      // approve(spender, amount)
      const normalizedAmount = typeof amount === 'string' 
        ? ethers.BigNumber.from(amount)
        : amount;
      
      if (normalizedAmount.eq(ethers.constants.MaxUint256)) {
        params = [normalizeAddress(spenderAddress), true]; // Use boolean for max uint256
      } else {
        params = [normalizeAddress(spenderAddress), normalizedAmount.toString()];
      }
    }

    const estimatedGas = 40000; // Approximate for ERC-20 operations

    return {
      tokenAddress,
      spenderAddress,
      amount: amount || ethers.BigNumber.from(0),
      isApprovedForAll,
      method,
      params,
      estimatedGas,
    };
  }

  async buildNFTRevoke(
    nftAddress: Address,
    tokenId: string,
    spenderAddress: Address,
    isApprovedForAll: boolean = false
  ): Promise<RevokeTransaction> {
    const method = isApprovedForAll 
      ? 'setApprovalForAll' 
      : 'approve';

    let params: any[];
    
    if (isApprovedForAll) {
      // setApprovalForAll(spender, approved)
      params = [normalizeAddress(spenderAddress), false];
    } else {
      // approve(spender, tokenId)
      params = [normalizeAddress(spenderAddress), ethers.BigNumber.from(tokenId)];
    }

    const estimatedGas = 60000; // NFT operations typically need more gas

    return {
      tokenAddress: nftAddress,
      spenderAddress,
      amount: ethers.BigNumber.from(0),
      isApprovedForAll,
      method,
      params,
      estimatedGas,
    };
  }

  async estimateGas(transaction: RevokeTransaction): Promise<number> {
    if (!this.signer) {
      return transaction.estimatedGas;
    }

    try {
      const contract = new ethers.Contract(
        transaction.tokenAddress,
        [
          'function approve(address spender, uint256 amount) returns (bool)',
          'function setApprovalForAll(address operator, bool approved) returns (bool)',
        ],
        this.signer
      );

      const tx = contract[transaction.method](...transaction.params);
      return await tx.estimateGas();
    } catch (e) {
      console.warn('Failed to estimate gas:', e);
      return transaction.estimatedGas;
    }
  }

  async executeRevoke(transaction: RevokeTransaction): Promise<ethers.TransactionResponse> {
    if (!this.signer) {
      throw new Error('No signer configured');
    }

    const contract = new ethers.Contract(
      transaction.tokenAddress,
      [
        'function approve(address spender, uint256 amount) returns (bool)',
        'function setApprovalForAll(address operator, bool approved) returns (bool)',
      ],
      this.signer
    );

    const tx = contract[transaction.method](...transaction.params);
    
    // Wait for confirmation
    await tx.wait();
    
    return tx;
  }

  async executeBatchRevoke(revokes: RevokeTransaction[]): Promise<ethers.TransactionResponse[]> {
    if (!this.signer) {
      throw new Error('No signer configured');
    }

    const provider = this.provider as ethers.JsonRpcProvider;
    
    // Build multicall transaction
    const calls: any[] = [];
    for (const revoke of revokes) {
      const contract = new ethers.Contract(
        revoke.tokenAddress,
        [
          'function approve(address spender, uint256 amount) returns (bool)',
          'function setApprovalForAll(address operator, bool approved) returns (bool)',
        ],
        this.signer
      );

      calls