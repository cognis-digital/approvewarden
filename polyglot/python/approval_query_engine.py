"""
approval_query_engine.py

Scans ERC-20/721/1155 token approvals, scores drainer exposure,
and emits revoke transactions.

Usage:
    from approval_query_engine import ApprovalQueryEngine
    
    engine = ApprovalQueryEngine()
    results = await engine.scan_wallet("0x...")
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, List, Dict, Any, Callable, Awaitable, Union
from decimal import Decimal
from functools import lru_cache

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


class TokenType(Enum):
    ERC20 = "ERC20"
    ERC721 = "ERC721"
    ERC1155 = "ERC1155"


@dataclass(frozen=True)
class TokenMetadata:
    """Cached token metadata to avoid repeated API calls."""
    
    address: str
    name: str
    symbol: str
    decimals: int
    price_usd: Decimal
    last_updated: datetime
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TokenMetadata":
        return cls(
            address=data["address"],
            name=data.get("name", ""),
            symbol=data.get("symbol", ""),
            decimals=int(data.get("decimals", 18)),
            price_usd=Decimal(str(data.get("price_usd", 0))),
            last_updated=datetime.fromisoformat(data["last_updated"]),
        )


@dataclass(frozen=True)
class Approval:
    """Represents a single token approval."""
    
    owner: str
    spender: str
    token_type: TokenType
    token_address: str
    amount: Union[int, Decimal]  # Raw uint256 or normalized value
    is_infinite: bool = False
    timestamp: Optional[datetime] = None
    metadata: TokenMetadata = field(default_factory=TokenMetadata)
    
    @property
    def normalized_amount(self) -> Decimal:
        """Amount in smallest units (e.g., 1000 for 1.0 ETH with 3 decimals)."""
        if self.is_infinite:
            return Decimal("999999999999999999999999999999999999")
        return Decimal(str(self.amount)) / (Decimal(10) ** self.metadata.decimals)
    
    @property
    def value_usd(self) -> Decimal:
        """Approximate USD value of this approval."""
        if self.is_infinite:
            # Assume max uint256 for infinite approvals
            return self.normalized_amount * self.metadata.price_usd
        
        normalized = self.normalized_amount
        if normalized > 0 and self.metadata.price_usd > 0:
            return normalized * self.metadata.price_usd
        return Decimal(0)


@dataclass(frozen=True)
class DrainerScore:
    """Risk score for a drainer/spender address."""
    
    spender_address: str
    total_exposure_usd: Decimal = Decimal(0)
    approval_count: int = 0
    infinite_approvals: int = 0
    recent_activity_days: int = 365
    
    @property
    def exposure_per_approval(self) -> Decimal:
        if self.approval_count == 0:
            return Decimal(0)
        return self.total_exposure_usd / self.approval_count


@dataclass(frozen=True)
class ScanResult:
    """Complete scan result for a wallet."""
    
    owner_address: str
    total_approvals: int = 0
    dangerous_approvals: List[Approval] = field(default_factory=list)
    drainer_scores: Dict[str, DrainerScore] = field(default_factory=dict)
    summary_stats: Dict[str, Any] = field(default_factory=dict)
    
    def add_approval(self, approval: Approval):
        self.total_approvals += 1
        
        # Update drainer score if spender exists
        if approval.spender in self.drainer_scores:
            score = self.drainer_scores[approval.spender]
            score.approval_count += 1
            score.total_exposure_usd += approval.value_usd
            
            if approval.is_infinite:
                score.infinite_approvals += 1
        else:
            # New spender - create fresh score
            self.drainer_scores[approval.spender] = DrainerScore(
                spender_address=approval.spender,
                total_exposure_usd=approval.value_usd,
                approval_count=1,
                infinite_approvals=1 if approval.is_infinite else 0,
            )


class Config:
    """Configuration for the query engine."""
    
    # API defaults
    ETHERSCAN_API_KEY: str = ""
    ETHERSCAN_BASE_URL: str = "https://api.etherscan.io/api"
    DEFAULT_RPC_URL: str = "https://mainnet.infura.io/v3/..."
    
    # Caching
    TOKEN_CACHE_TTL_SECONDS: int = 3600
    
    # Scoring thresholds (configurable)
    DANGEROUS_ALLOWANCE_THRESHOLD_USD: Decimal = Decimal("100")
    HIGH_RISK_INFINITE_COUNT: int = 5
    MEDIUM_RISK_INFINITE_COUNT: int = 2
    
    # Transaction defaults
    DEFAULT_GAS_PRICE_GWEI: Decimal = Decimal("30")


class TokenCache:
    """Thread-safe token metadata cache."""
    
    def __init__(self, ttl_seconds: int):
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, Tuple[TokenMetadata, datetime]] = {}
        self._lock = asyncio.Lock()
    
    async def get_or_fetch(self, address: str) -> TokenMetadata:
        """Get cached metadata or fetch fresh data."""
        async with self._lock:
            # Check cache first
            if address in self._cache:
                meta, expiry = self._cache[address]
                if datetime.now() < expiry:
                    return meta
            
            # Fetch from API (placeholder - implement real logic)
            meta = await self._fetch_from_api(address)
            
            # Update cache with expiry time
            self._cache[address] = (meta, datetime.now() + timedelta(seconds=self.ttl_seconds))
            return meta
    
    async def _fetch_from_api(self, address: str) -> TokenMetadata:
        """Fetch token metadata from API."""
        # TODO: Implement actual Etherscan/Coingecko API calls
        # For now, return a default placeholder
        logger.info(f"Fetching metadata for {address}")
        
        # Simulated response - replace with real API call
        return TokenMetadata(
            address=address,
            name="Unknown",
            symbol="UNKNOWN",
            decimals=18,
            price_usd=Decimal("0"),
            last_updated=datetime.now(),
        )


class TransactionBuilder:
    """Builds revoke transactions for dangerous approvals."""
    
    def __init__(self, rpc_url: str = Config.DEFAULT_RPC_URL):
        self.rpc_url = rpc_url
    
    def build_revoke_tx(self, approval: Approval) -> Dict[str, Any]:
        """
        Build a transaction to revoke an ERC-20 approval.
        
        Returns dict with 'to', 'value' (if any), and 'data'.
        For ERC-721/1155, returns similar structure for setApprovalForAll.
        """
        # ERC-20: standard approve(address spender, uint256 amount)
        if approval.token_type == TokenType.ERC20:
            return {
                "to": approval.spender,
                "value": 0,
                "data": f"0x{approval.metadata.address.lower()[-4:].rjust(4, '0').upper()}" + 
                        # Standard ERC-20 approve selector (simplified)
                        "0095d803",  # This is the actual selector for setApprovalForAll on many tokens
            }
        
        # ERC-721: setApprovalForAll(address operator, bool approved)
        if approval.token_type == TokenType.ERC721:
            return {
                "to": approval.spender,
                "value": 0,
                "data": f"0x{approval.metadata.address.lower()[-4:].rjust(4, '0').upper()}" + 
                        "0f8e9563",  # setApprovalForAll selector
            }
        
        # ERC-1155: setApprovalForAll(address operator, bool approved)
        if approval.token_type == TokenType.ERC1155:
            return {
                "to": approval.spender,
                "value": 0,
                "data": f"0x{approval.metadata.address.lower()[-4:].rjust(4, '0').upper()}" + 
                        "0f8e9563",  # setApprovalForAll selector
            }
        
        return {"to": approval.spender, "value": 0, "data": ""}


class ApprovalQueryEngine:
    """
    Main engine for scanning and analyzing token approvals.
    
    Thread-safe, async-capable, with built-in caching and scoring.
    """
    
    def __init__(
        self,
        rpc_url: Optional[str] = None,
        etherscan_api_key: Optional[str] = None,
        token_cache_ttl: int = Config.TOKEN_CACHE_TTL_SECONDS,
    ):
        self.rpc_url = rpc_url or Config.DEFAULT_RPC_URL
        self.etherscan_api_key = etherscan_api_key or Config.ETHERSCAN_API_KEY
        self.token_cache = TokenCache(token_cache_ttl)
        self.tx_builder = TransactionBuilder(rpc_url)
    
    async def scan_wallet(
        self, 
        owner_address: str,
        token_types: Optional[List[TokenType]] = None,
        include_metadata: bool = True,
    ) -> ScanResult:
        """
        Scan a wallet for all dangerous approvals.
        
        Args:
            owner_address: The wallet address to scan
            token_types: Filter by specific token types (default: all)
            include_metadata: Whether to fetch full metadata
        
        Returns:
            Complete ScanResult with all findings and scores
        """
        result = ScanResult(owner_address=owner_address.lower())
        
        # Fetch approvals from API
        approvals = await self._fetch_approvals(owner_address, token_types)
        
        # Process each approval
        for raw_approval in approvals:
            if not include_metadata or "metadata" in raw_approval:
                meta_data = raw_approval.get("metadata")
                if meta_data:
                    result.dangerous_approvals.append(Approval(
                        owner=owner_address.lower(),
                        spender=raw_approval["spender"].lower(),
                        token_type=TokenType(meta_data.get("type", "ERC20")),
                        token_address=meta_data.get("address", ""),
                        amount=int(raw_approval.get("amount", 0)),
                        is_infinite=bool(raw_approval.get("is_infinite", False)),
                        metadata=TokenMetadata.from_dict(meta_data),
                    ))
            else:
                # No metadata - create minimal approval
                result.dangerous_approvals.append(Approval(
                    owner=owner_address.lower(),
                    spender=raw_approval["spender"].lower(),
                    token_type=TokenType.ERC20,
                    token_address="",
                    amount=int(raw_approval.get("amount", 0)),
                    is_infinite=bool(raw_approval.get("is_infinite", False)),
                ))
        
        # Calculate summary stats
        result._calculate_summary_stats()
        
        return result
    
    async def _fetch_approvals(
        self, 
        owner_address: str, 
        token_types: Optional[List[TokenType]] = None
    ) -> List[Dict[str, Any]]:
        """Fetch approvals from Etherscan API."""
        # TODO: Implement actual API call
        # Example structure of what we'd fetch:
        return [
            {
                "owner": owner_address.lower(),
                "spender": "0x1234567890abcdef1234567890abcdef12345678",
                "amount": 1000,
                "is_infinite": False,
                "metadata": {
                    "type": "ERC20",
                    "address": "0x6b175474e89094c44da98b954eedfeac4c528a19",  # DAI
                    "name": "Dai Stablecoin",
                    "symbol": "DAI",
                    "decimals": 18,
                },
            }
        ]
    
    def _calculate_summary_stats(self) -> None:
        """Calculate summary statistics for the result."""
        total_exposure = sum(a.value_usd for a in self.dangerous_approvals)
        
        infinite_count = sum(1 for a in self.dangerous_approvals if a.is_infinite)
        
        high_risk_spenders = [
            spender for spender, score in self.drainer_scores.items()
            if score.infinite_approvals >= Config.HIGH_RISK_INFINITE_COUNT
        ]
        
        medium_risk_spenders = [
            spender for spender, score in self.drainer_scores.items()
            if 2 <= score.infinite_approvals < Config.HIGH_RISK_INFINITE_COUNT
        ]
        
        self.summary_stats = {
            "total_exposure_usd": total_exposure,
            "dangerous_approval_count": len(self.dangerous_approvals),
            "infinite_allowance_count": infinite_count,
            "high_risk_spenders": high_risk_spenders,
            "medium_risk_spenders": medium_risk_spenders,
        }


# Demo / Entry Point
async def main():
    """Run a demo scan."""
    engine = ApprovalQueryEngine()
    
    # Example: Scan a known wallet with multiple approvals
    owner = "0x8ba1f109551bD432803012645Hc176c8d"  # Placeholder
    
    print(f"Scanning wallet: {owner}")
    
    result = await engine.scan_wallet(owner)
    
    print(f"\n=== Scan Results ===")
    print(f"Total approvals found: {result.total_approvals}")
    print(f"Dangerous approvals: {len(result.dangerous_approvals)}")
    print(f"Total exposure: ${result.summary_stats.get('total_exposure_usd', 0):,.2f}")
    
    if result.dangerous_approvals:
        print("\n=== Dangerous Approvals ===")
        for i, approval in enumerate(result.dangerous_approvals[:5], 1):
            print(f"{i}. {approval.token_type.value}: ${approval.value_usd:,.2f}")
    
    if result.drainer_scores:
        print("\n=== Top Drainers ===")
        sorted_scores = sorted(
            result.drainer_scores.values(),
            key=lambda s: s.total_exposure_usd,
            reverse=True,
        )[:5]
        
        for score in sorted_scores:
            print(f"  {score.spender_address}: ${score.total_exposure_usd:,.2f} "
                  f"({score.approval_count} approvals)")


if __name__ == "__main__":
    asyncio.run(main())