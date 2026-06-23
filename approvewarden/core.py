"""Core approval-audit engine for APPROVEWARDEN.

Pure standard library. No network calls -- approvals are supplied as data
(exported from an explorer/indexer) so the auditor is deterministic and
CI-friendly.

An *approval* is a record describing that ``owner`` has granted ``spender`` an
allowance over a token. We detect:

* infinite / unlimited allowances (uint256 max, uint96 max, or absurdly large),
* ERC-721 / ERC-1155 ``setApprovalForAll`` blanket grants,
* approvals to spenders flagged as known drainers / unverified,
* stale approvals (granted long ago, never revoked).

Each approval gets a 0-100 risk score and a severity bucket; the wallet gets an
aggregate exposure score.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Iterable

# --- tool identity ---------------------------------------------------------
# Read the single source of truth (the VERSION file) when packaged alongside
# the module; fall back to a literal so imports never fail.
TOOL_NAME = "approvewarden"


def _read_version() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    for candidate in (
        os.path.join(here, "..", "VERSION"),
        os.path.join(here, "VERSION"),
    ):
        try:
            with open(candidate, "r", encoding="utf-8") as fh:
                v = fh.read().strip()
                if v:
                    return v
        except OSError:
            continue
    return "0.2.0"


TOOL_VERSION = _read_version()

# Common sentinel values used by contracts to mean "unlimited".
UINT256_MAX = (1 << 256) - 1
UINT96_MAX = (1 << 96) - 1  # Uniswap Permit2 / UNI-style "infinite".
# Anything above this many whole tokens (assuming 18 decimals) we treat as
# effectively infinite even if not exactly a sentinel -- no legitimate grant
# needs 10^15 tokens of headroom.
EFFECTIVE_INFINITE_RAW = 10 ** (15 + 18)

_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class ApprovalError(ValueError):
    """Raised when an approval record cannot be parsed."""


def normalize_address(value: Any) -> str:
    """Validate and lower-case a hex address. Raises on garbage."""
    if value is None:
        raise ApprovalError("address is missing")
    s = str(value).strip()
    if not _ADDR_RE.match(s):
        raise ApprovalError(f"invalid address: {value!r}")
    return s.lower()


def _parse_amount(value: Any) -> int:
    """Parse an allowance amount.

    Accepts ints, decimal strings, hex strings (0x...), and the literal
    sentinels ``max``/``unlimited``/``infinite``.
    """
    if value is None:
        return 0
    if isinstance(value, bool):  # guard: bool is an int subclass
        raise ApprovalError("amount cannot be a boolean")
    if isinstance(value, int):
        return value
    s = str(value).strip().lower().replace("_", "").replace(",", "")
    if s in ("", "none", "null"):
        return 0
    if s in ("max", "unlimited", "infinite", "inf"):
        return UINT256_MAX
    try:
        if s.startswith("0x"):
            return int(s, 16)
        # tolerate float-ish exports like "1.0e30"
        if "e" in s or "." in s:
            return int(float(s))
        return int(s)
    except ValueError as exc:
        raise ApprovalError(f"invalid amount: {value!r}") from exc


# A small built-in deny-list of spender *labels* that indicate known-bad or
# unaudited contracts. Real deployments would extend this; the point is that
# a labelled malicious spender escalates severity regardless of amount. These
# are generic family names that wallet explorers (Etherscan, GoPlus, Scam
# Sniffer) attach to flagged spenders -- not fabricated addresses.
KNOWN_DRAINER_LABELS = {
    "drainer",
    "phishing",
    "inferno",
    "pink-drainer",
    "angel-drainer",
    "monkey-drainer",
    "venom-drainer",
    "ms-drainer",
    "scam",
    "malicious",
    "fake-permit",
    "approval-farming",
    "wallet-drainer",
}

# Optional address deny-list. Empty by default -- callers load their own from
# a feed/file via ``load_drainer_addresses``. We ship NO hard-coded addresses
# so the tool never makes unverified on-chain accusations.
KNOWN_DRAINER_ADDRESSES: set[str] = set()


def load_drainer_addresses(addresses: Iterable[str]) -> set[str]:
    """Validate + normalize a caller-supplied address deny-list.

    Returns the set of normalized addresses. Invalid entries are skipped so a
    single bad line never breaks a scan.
    """
    out: set[str] = set()
    for a in addresses:
        try:
            out.add(normalize_address(a))
        except ApprovalError:
            continue
    return out


@dataclass
class Approval:
    """A single token approval record."""

    token: str
    token_symbol: str
    spender: str
    amount: int
    standard: str = "ERC20"  # ERC20 | ERC721 | ERC1155
    is_approval_for_all: bool = False
    spender_label: str = ""
    spender_verified: bool = True
    last_updated: int | None = None  # unix seconds
    owner: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Approval":
        if not isinstance(d, dict):
            raise ApprovalError("approval record must be an object")
        standard = str(d.get("standard", "ERC20")).upper().strip() or "ERC20"
        afa = d.get("is_approval_for_all", d.get("approval_for_all", False))
        if isinstance(afa, str):
            afa = afa.strip().lower() in ("1", "true", "yes", "y")
        afa = bool(afa)
        verified = d.get("spender_verified", True)
        if isinstance(verified, str):
            verified = verified.strip().lower() not in ("0", "false", "no", "n", "")
        last = d.get("last_updated")
        if last in ("", None):
            last = None
        elif not isinstance(last, int):
            try:
                last = int(float(str(last)))
            except ValueError:
                last = None
        # For setApprovalForAll there is no numeric amount; treat enabled as
        # infinite exposure.
        if afa:
            amount = UINT256_MAX
        else:
            amount = _parse_amount(d.get("amount", d.get("allowance", 0)))
        return cls(
            token=normalize_address(d.get("token", d.get("contract"))),
            token_symbol=str(d.get("token_symbol", d.get("symbol", ""))).strip(),
            spender=normalize_address(d.get("spender")),
            amount=amount,
            standard=standard,
            is_approval_for_all=afa,
            spender_label=str(d.get("spender_label", d.get("label", ""))).strip(),
            spender_verified=bool(verified),
            last_updated=last,
            owner=str(d.get("owner", "")).strip().lower(),
            raw=d,
        )


@dataclass
class Finding:
    """Scored result for one approval."""

    token: str
    token_symbol: str
    spender: str
    spender_label: str
    standard: str
    allowance_kind: str  # zero | finite | effectively_infinite | infinite | blanket
    severity: str
    score: int
    reasons: list[str]
    amount: int

    def to_dict(self) -> dict[str, Any]:
        d = {
            "token": self.token,
            "token_symbol": self.token_symbol,
            "spender": self.spender,
            "spender_label": self.spender_label,
            "standard": self.standard,
            "allowance_kind": self.allowance_kind,
            "severity": self.severity,
            "score": self.score,
            "reasons": self.reasons,
            # amount can exceed JSON-safe int range conceptually but Python/JSON
            # handle big ints fine; emit as string for downstream safety.
            "amount": str(self.amount),
        }
        return d


def classify_allowance(approval: Approval) -> str:
    """Bucket the raw allowance magnitude."""
    if approval.is_approval_for_all:
        return "blanket"
    amt = approval.amount
    if amt <= 0:
        return "zero"
    if amt == UINT256_MAX or amt == UINT96_MAX:
        return "infinite"
    if amt >= EFFECTIVE_INFINITE_RAW:
        return "effectively_infinite"
    return "finite"


def score_approval(
    approval: Approval,
    now: int | None = None,
    denylist: set[str] | None = None,
) -> Finding:
    """Produce a 0-100 risk score + severity for a single approval.

    ``denylist`` is an optional set of normalized spender addresses known to be
    malicious; a hit escalates the finding to critical regardless of amount.
    """
    now = int(time.time()) if now is None else now
    kind = classify_allowance(approval)
    reasons: list[str] = []
    score = 0

    if kind == "zero":
        # Nothing granted -> not a finding.
        return Finding(
            token=approval.token,
            token_symbol=approval.token_symbol,
            spender=approval.spender,
            spender_label=approval.spender_label,
            standard=approval.standard,
            allowance_kind=kind,
            severity="info",
            score=0,
            reasons=["no active allowance"],
            amount=approval.amount,
        )

    if kind == "blanket":
        score += 60
        reasons.append(
            f"setApprovalForAll grants the spender control of ALL {approval.standard} tokens"
        )
    elif kind == "infinite":
        score += 55
        reasons.append("unlimited allowance (uint256/uint96 max sentinel)")
    elif kind == "effectively_infinite":
        score += 45
        reasons.append("allowance is astronomically large (effectively infinite)")
    else:  # finite
        score += 10
        reasons.append("finite, bounded allowance")

    label = approval.spender_label.lower()
    dl = denylist if denylist is not None else KNOWN_DRAINER_ADDRESSES
    addr_flagged = bool(dl) and approval.spender in dl
    label_flagged = bool(label) and any(bad in label for bad in KNOWN_DRAINER_LABELS)
    if addr_flagged:
        score += 100
        reasons.append(
            f"spender address {approval.spender} is on the drainer deny-list"
        )
    elif label_flagged:
        score += 100
        reasons.append(f"spender labelled as known-malicious ({approval.spender_label})")
    elif not approval.spender_verified:
        score += 25
        reasons.append("spender contract is unverified")

    # Staleness: a long-lived, never-revoked grant widens the attack window.
    if approval.last_updated is not None:
        age_days = max(0, (now - approval.last_updated) // 86400)
        if age_days >= 365:
            score += 15
            reasons.append(f"stale approval (~{age_days} days old, never revoked)")
        elif age_days >= 180:
            score += 8
            reasons.append(f"aging approval (~{age_days} days old)")

    score = max(0, min(100, score))

    if score >= 80:
        severity = "critical"
    elif score >= 55:
        severity = "high"
    elif score >= 30:
        severity = "medium"
    elif score >= 1:
        severity = "low"
    else:
        severity = "info"

    return Finding(
        token=approval.token,
        token_symbol=approval.token_symbol,
        spender=approval.spender,
        spender_label=approval.spender_label,
        standard=approval.standard,
        allowance_kind=kind,
        severity=severity,
        score=score,
        reasons=reasons,
        amount=approval.amount,
    )


def _coerce_records(data: Any) -> list[dict[str, Any]]:
    """Accept either a list of approvals or an object with an 'approvals' key."""
    if isinstance(data, list):
        return [r for r in data]
    if isinstance(data, dict):
        if "approvals" in data and isinstance(data["approvals"], list):
            return data["approvals"]
        # single record object
        return [data]
    raise ApprovalError("input JSON must be a list or an object")


def load_approvals_from_text(text: str, fmt: str = "auto") -> list[Approval]:
    """Parse approvals from a JSON or CSV string.

    fmt: 'json', 'csv', or 'auto' (sniff by content).
    """
    fmt = (fmt or "auto").lower()
    stripped = text.lstrip()
    if fmt == "auto":
        fmt = "json" if stripped[:1] in ("[", "{") else "csv"

    records: list[dict[str, Any]]
    if fmt == "json":
        records = _coerce_records(json.loads(text))
    elif fmt == "csv":
        reader = csv.DictReader(io.StringIO(text))
        records = [dict(row) for row in reader]
    else:
        raise ApprovalError(f"unknown format: {fmt}")

    approvals: list[Approval] = []
    for i, rec in enumerate(records):
        try:
            approvals.append(Approval.from_dict(rec))
        except ApprovalError as exc:
            raise ApprovalError(f"record {i}: {exc}") from exc
    return approvals


def load_approvals(path: str, fmt: str = "auto") -> list[Approval]:
    """Load approvals from a JSON or CSV file on disk."""
    if fmt == "auto":
        if path.lower().endswith(".csv"):
            fmt = "csv"
        elif path.lower().endswith(".json"):
            fmt = "json"
    with open(path, "r", encoding="utf-8") as fh:
        return load_approvals_from_text(fh.read(), fmt=fmt)


def audit_approvals(
    approvals: Iterable[Approval],
    now: int | None = None,
    denylist: set[str] | None = None,
) -> dict[str, Any]:
    """Audit a set of approvals and return an aggregate report dict."""
    findings = [score_approval(a, now=now, denylist=denylist) for a in approvals]
    # Only allowances that actually grant something are "findings".
    active = [f for f in findings if f.allowance_kind != "zero"]

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in active:
        counts[f.severity] += 1

    infinite_like = [
        f
        for f in active
        if f.allowance_kind in ("infinite", "effectively_infinite", "blanket")
    ]

    # Wallet-level exposure: emphasise the worst offenders rather than a flat
    # mean, so one critical grant dominates. Weighted average where higher
    # scores carry more weight (score acts as its own weight, +1 floor).
    if active:
        weights = [f.score + 1 for f in active]
        risk_score = round(
            sum(f.score * w for f, w in zip(active, weights)) / sum(weights)
        )
        # never report lower than the single worst finding
        risk_score = max(risk_score, max(f.score for f in active))
    else:
        risk_score = 0

    if risk_score >= 80:
        risk_level = "critical"
    elif risk_score >= 55:
        risk_level = "high"
    elif risk_score >= 30:
        risk_level = "medium"
    elif risk_score >= 1:
        risk_level = "low"
    else:
        risk_level = "clean"

    active_sorted = sorted(active, key=lambda f: f.score, reverse=True)

    return {
        "tool": "approvewarden",
        "total_approvals": len(findings),
        "active_approvals": len(active),
        "infinite_approvals": len(infinite_like),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "severity_counts": counts,
        "summary": (
            f"{len(active)} active approval(s), {len(infinite_like)} infinite/blanket, "
            f"risk={risk_score}/100 ({risk_level})"
        ),
        "findings": [f.to_dict() for f in active_sorted],
        "clean": len(active) == 0,
    }


# ---------------------------------------------------------------------------
# High-level convenience API (used by the MCP server, agents, and the CLI)
# ---------------------------------------------------------------------------

def scan(
    target: str,
    fmt: str = "auto",
    now: int | None = None,
    denylist: set[str] | None = None,
) -> dict[str, Any]:
    """Load an approval export from ``target`` (a JSON/CSV path) and audit it.

    This is the one-call entry point: ``scan("approvals.json")`` returns the
    same report dict as ``audit_approvals``. Fully offline -- ``target`` must be
    a local file produced by an explorer/indexer export.
    """
    approvals = load_approvals(target, fmt=fmt)
    return audit_approvals(approvals, now=now, denylist=denylist)


def to_json(report: dict[str, Any], indent: int = 2) -> str:
    """Serialize a report dict to a JSON string."""
    return json.dumps(report, indent=indent)


def revoke_plan(report: dict[str, Any], min_severity: str = "high") -> list[dict[str, Any]]:
    """Build a read-only, copy-pasteable revoke plan from a report.

    For every finding at/above ``min_severity`` we describe the exact call the
    wallet owner would make to revoke -- ``approve(spender, 0)`` for ERC-20 or
    ``setApprovalForAll(spender, false)`` for ERC-721/1155. We DO NOT sign,
    broadcast, or build raw transactions: this is advisory output only.
    """
    threshold = SEVERITY_ORDER.get(min_severity, SEVERITY_ORDER["high"])
    plan: list[dict[str, Any]] = []
    for f in report.get("findings", []):
        if SEVERITY_ORDER.get(f["severity"], 0) < threshold:
            continue
        standard = f["standard"].upper()
        if f["allowance_kind"] == "blanket" or standard in ("ERC721", "ERC1155"):
            method = "setApprovalForAll"
            args = [f["spender"], False]
            signature = f"setApprovalForAll({f['spender']}, false)"
        else:
            method = "approve"
            args = [f["spender"], 0]
            signature = f"approve({f['spender']}, 0)"
        plan.append(
            {
                "token": f["token"],
                "token_symbol": f["token_symbol"],
                "spender": f["spender"],
                "standard": standard,
                "severity": f["severity"],
                "score": f["score"],
                "method": method,
                "args": args,
                "call": signature,
                "note": "advisory only -- review and sign in your own wallet",
            }
        )
    return plan


def to_sarif(report: dict[str, Any], source_file: str = "approvals.json") -> dict[str, Any]:
    """Render the report as a SARIF 2.1.0 document for code-scanning dashboards.

    Each active approval becomes a SARIF result; severity maps to SARIF level
    (error/warning/note). Useful for GitHub code-scanning and any SARIF viewer.
    """
    level_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in report.get("findings", []):
        rule_id = f"approvewarden/{f['allowance_kind']}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f["allowance_kind"].replace("_", " ").title().replace(" ", ""),
                "shortDescription": {"text": f"{f['allowance_kind']} token allowance"},
                "defaultConfiguration": {"level": level_map.get(f["severity"], "warning")},
            }
        sym = f["token_symbol"] or f["token"]
        results.append(
            {
                "ruleId": rule_id,
                "level": level_map.get(f["severity"], "warning"),
                "message": {
                    "text": (
                        f"{sym}: {f['allowance_kind']} allowance to "
                        f"{f['spender_label'] or f['spender']} "
                        f"(score {f['score']}/100) -- " + "; ".join(f["reasons"])
                    )
                },
                "properties": {
                    "score": f["score"],
                    "severity": f["severity"],
                    "spender": f["spender"],
                    "token": f["token"],
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": source_file},
                        }
                    }
                ],
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "approvewarden",
                        "version": TOOL_VERSION,
                        "informationUri": "https://github.com/cognis-digital/approvewarden",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
