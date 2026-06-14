"""Hardening tests — edge cases, bad input, and error paths.

All tests are offline (no network). They must never modify the demo files.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from approvewarden.core import (
    ApprovalError,
    load_approvals,
    load_approvals_from_text,
    audit_approvals,
)

ROOT = os.path.dirname(os.path.dirname(__file__))


# ---------------------------------------------------------------------------
# load_approvals_from_text — bad / edge input
# ---------------------------------------------------------------------------


def test_empty_string_returns_empty_list():
    """Empty input is valid and yields zero approvals (not an error)."""
    result = load_approvals_from_text("")
    assert result == []


def test_whitespace_only_returns_empty_list():
    result = load_approvals_from_text("   \n  \t ")
    assert result == []


def test_malformed_json_raises_approval_error():
    with pytest.raises(ApprovalError, match="invalid JSON"):
        load_approvals_from_text("{not valid json}", fmt="json")


def test_json_wrong_root_type_raises():
    """A bare string or number at root is not a valid approvals payload."""
    with pytest.raises(ApprovalError):
        load_approvals_from_text('"just a string"', fmt="json")


def test_null_item_in_json_list_raises():
    """A null inside the approvals list should raise a clear error."""
    with pytest.raises(ApprovalError, match="record 0"):
        load_approvals_from_text("[null]", fmt="json")


def test_unknown_format_raises():
    with pytest.raises(ApprovalError, match="unknown format"):
        load_approvals_from_text("[{}]", fmt="xml")


def test_csv_empty_body_returns_empty():
    """A CSV with just a header and no data rows is valid."""
    csv_text = "token,symbol,spender,amount\n"
    result = load_approvals_from_text(csv_text, fmt="csv")
    assert result == []


def test_missing_required_address_field_raises():
    """An approval missing the token address must raise ApprovalError."""
    record = json.dumps([{"spender": "0x" + "22" * 20, "amount": "0"}])
    with pytest.raises(ApprovalError, match="record 0"):
        load_approvals_from_text(record, fmt="json")


def test_invalid_address_raises():
    record = json.dumps(
        [{"token": "not-an-address", "spender": "0x" + "22" * 20, "amount": "0"}]
    )
    with pytest.raises(ApprovalError, match="record 0"):
        load_approvals_from_text(record, fmt="json")


# ---------------------------------------------------------------------------
# load_approvals — file not found
# ---------------------------------------------------------------------------


def test_load_approvals_missing_file_raises():
    with pytest.raises(ApprovalError, match="file not found"):
        load_approvals("/nonexistent/path/approvals.json")


def test_load_approvals_empty_path_raises():
    with pytest.raises(ApprovalError):
        load_approvals("")


# ---------------------------------------------------------------------------
# audit_approvals — empty collection
# ---------------------------------------------------------------------------


def test_audit_empty_approvals():
    """audit_approvals must not divide by zero on an empty list."""
    report = audit_approvals([])
    assert report["total_approvals"] == 0
    assert report["active_approvals"] == 0
    assert report["risk_score"] == 0
    assert report["clean"] is True
    assert report["findings"] == []


# ---------------------------------------------------------------------------
# CLI error paths
# ---------------------------------------------------------------------------


def test_cli_missing_file_exits_1():
    """Scanning a non-existent file must exit with code 1 and print to stderr."""
    proc = subprocess.run(
        [sys.executable, "-m", "approvewarden", "scan", "/no/such/file.json"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert proc.returncode == 1
    assert proc.stderr.strip() != ""


def test_cli_malformed_json_exits_1(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid}", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "approvewarden", "scan", str(bad)],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert proc.returncode == 1
    assert "error" in proc.stderr.lower()


def test_cli_empty_json_file_exits_0(tmp_path):
    """An empty file is valid (zero approvals) and should exit 0."""
    empty = tmp_path / "empty.json"
    empty.write_text("", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "approvewarden", "scan", str(empty),
         "--format", "json"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["clean"] is True
    assert payload["total_approvals"] == 0


def test_cli_no_subcommand_exits_1():
    """Invoking with no subcommand should print help and exit 1."""
    proc = subprocess.run(
        [sys.executable, "-m", "approvewarden"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert proc.returncode == 1


def test_cli_clean_wallet_exits_0(tmp_path):
    """A wallet with only zero-allowances should exit 0 (no risky findings)."""
    data = json.dumps(
        [
            {
                "token": "0x" + "11" * 20,
                "symbol": "OK",
                "spender": "0x" + "22" * 20,
                "amount": "0",
            }
        ]
    )
    clean = tmp_path / "clean.json"
    clean.write_text(data, encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "approvewarden", "scan", str(clean),
         "--fail-on", "high"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert proc.returncode == 0
