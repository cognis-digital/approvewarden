"""Smoke tests for APPROVEWARDEN. No network access."""

import json
import os
import subprocess
import sys

import pytest

from approvewarden import (
    TOOL_NAME,
    TOOL_VERSION,
    audit_approvals,
    classify_allowance,
    load_approvals,
    load_approvals_from_text,
    normalize_address,
    score_approval,
)
from approvewarden.core import UINT256_MAX, Approval, ApprovalError

DEMO = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "demos", "01-basic", "approvals.json"
)
# A fixed 'now' so staleness scoring is deterministic (2026-06-08).
NOW = 1749340800


def _load():
    return load_approvals(DEMO)


def test_metadata():
    assert TOOL_NAME == "approvewarden"
    assert TOOL_VERSION.count(".") == 2


def test_load_demo():
    approvals = _load()
    assert len(approvals) == 6
    assert all(isinstance(a, Approval) for a in approvals)
    symbols = {a.token_symbol for a in approvals}
    assert {"USDC", "WETH", "DAI", "BAYC", "LINK", "SHIB"} == symbols


def test_normalize_address():
    assert normalize_address("0x" + "Ab" * 20) == "0x" + "ab" * 20
    with pytest.raises(ApprovalError):
        normalize_address("not-an-address")
    with pytest.raises(ApprovalError):
        normalize_address("0x1234")


def test_classify():
    approvals = {a.token_symbol: a for a in _load()}
    assert classify_allowance(approvals["USDC"]) == "infinite"
    assert classify_allowance(approvals["WETH"]) == "finite"
    assert classify_allowance(approvals["DAI"]) == "effectively_infinite"
    assert classify_allowance(approvals["BAYC"]) == "blanket"
    assert classify_allowance(approvals["SHIB"]) == "zero"


def test_known_drainer_is_critical():
    approvals = {a.token_symbol: a for a in _load()}
    bayc = score_approval(approvals["BAYC"], now=NOW)
    assert bayc.severity == "critical"
    assert bayc.score >= 80
    assert any("malicious" in r.lower() for r in bayc.reasons)


def test_finite_is_low():
    approvals = {a.token_symbol: a for a in _load()}
    weth = score_approval(approvals["WETH"], now=NOW)
    assert weth.severity == "low"
    assert weth.allowance_kind == "finite"


def test_zero_is_not_a_finding():
    approvals = {a.token_symbol: a for a in _load()}
    shib = score_approval(approvals["SHIB"], now=NOW)
    assert shib.allowance_kind == "zero"
    assert shib.score == 0


def test_stale_unlimited_flagged():
    approvals = {a.token_symbol: a for a in _load()}
    link = score_approval(approvals["LINK"], now=NOW)
    assert link.allowance_kind == "infinite"
    assert any("stale" in r.lower() for r in link.reasons)


def test_audit_report():
    report = audit_approvals(_load(), now=NOW)
    assert report["total_approvals"] == 6
    assert report["active_approvals"] == 5  # SHIB revoked dropped
    # USDC infinite, DAI effectively-infinite, BAYC blanket, LINK infinite
    assert report["infinite_approvals"] == 4
    assert report["risk_level"] == "critical"
    assert report["risk_score"] >= 80
    assert report["clean"] is False
    # findings sorted worst-first
    scores = [f["score"] for f in report["findings"]]
    assert scores == sorted(scores, reverse=True)
    assert report["findings"][0]["token_symbol"] == "BAYC"


def test_clean_wallet():
    text = json.dumps(
        [
            {
                "token": "0x" + "11" * 20,
                "symbol": "OK",
                "spender": "0x" + "22" * 20,
                "amount": "0",
            }
        ]
    )
    report = audit_approvals(load_approvals_from_text(text), now=NOW)
    assert report["clean"] is True
    assert report["risk_level"] == "clean"
    assert report["risk_score"] == 0


def test_csv_parsing():
    csv_text = (
        "token,symbol,spender,amount,spender_verified\n"
        f"0x{'33' * 20},FOO,0x{'44' * 20},max,false\n"
    )
    approvals = load_approvals_from_text(csv_text, fmt="csv")
    assert len(approvals) == 1
    assert approvals[0].amount == UINT256_MAX
    assert approvals[0].spender_verified is False
    f = score_approval(approvals[0], now=NOW)
    assert f.allowance_kind == "infinite"
    assert any("unverified" in r for r in f.reasons)


def test_cli_json_and_exit_code():
    root = os.path.dirname(os.path.dirname(__file__))
    proc = subprocess.run(
        [sys.executable, "-m", "approvewarden", "scan", DEMO, "--format", "json"],
        capture_output=True,
        text=True,
        cwd=root,
    )
    # critical findings -> default --fail-on high trips -> exit 2
    assert proc.returncode == 2
    payload = json.loads(proc.stdout)
    assert payload["risk_level"] == "critical"
    assert payload["tool"] == "approvewarden"


def test_cli_version():
    root = os.path.dirname(os.path.dirname(__file__))
    proc = subprocess.run(
        [sys.executable, "-m", "approvewarden", "--version"],
        capture_output=True,
        text=True,
        cwd=root,
    )
    assert proc.returncode == 0
    assert TOOL_VERSION in proc.stdout
