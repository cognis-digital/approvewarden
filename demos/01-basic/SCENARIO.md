# Demo 01 - Basic approval audit

This demo audits a treasury wallet's exported ERC-20 / ERC-721 approval set
(`approvals.json`). No network access is required: the approvals are supplied
as data, exactly as an explorer or indexer (Etherscan, Covalent, an internal
subgraph) would export them.

## The data

`approvals.json` contains six approvals:

1. **USDC -> Uniswap V3 Router** with an **unlimited (uint256 max)** allowance,
   spender is verified. Classic infinite-approval risk.
2. **WETH -> a verified DEX aggregator** with a small **finite** allowance
   (1 WETH). Low risk -- this is normal, bounded usage.
3. **DAI -> an unverified contract** with an **effectively-infinite** allowance.
4. **BAYC (ERC-721) -> a spender labelled `Pink-Drainer`** via
   `setApprovalForAll`. A blanket grant to a known drainer -> **critical**.
5. **LINK -> an old verified router**, unlimited but stale (granted ~2 years
   ago, never revoked).
6. **SHIB -> a router** with a **zero** allowance (already revoked) -> not a
   finding.

## Run it

```bash
python -m approvewarden scan demos/01-basic/approvals.json
python -m approvewarden scan demos/01-basic/approvals.json --format json
```

## Expected result

- 6 total approvals, **5 active** (the revoked SHIB row is dropped).
- **3** infinite/blanket allowances (USDC, DAI effectively-infinite, BAYC
  blanket; LINK is also infinite -> actually 4 infinite-like).
- The **BAYC -> Pink-Drainer** finding scores ~100 and is **critical** (known
  malicious spender + blanket `setApprovalForAll`).
- Wallet `risk_level` is **critical** and `risk_score` >= 80.
- Because findings reach/exceed the default `--fail-on high` threshold, the CLI
  exits with code **2** (CI gate trips).
