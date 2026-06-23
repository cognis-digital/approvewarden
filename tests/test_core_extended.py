"""Extended unit tests for APPROVEWARDEN core scoring and parsing.

All offline, stdlib only. Uses a fixed `now` so staleness is deterministic.
"""
from __future__ import annotations

import json

import pytest

from approvewarden import (
    audit_approvals,
    classify_allowance,
    load_approvals_from_text,
    normalize_address,
    score_approval,
)
from approvewarden.core import (
    EFFECTIVE_INFINITE_RAW,
    KNOWN_DRAINER_LABELS,
    UINT96_MAX,
    UINT256_MAX,
    Approval,
    ApprovalError,
    _parse_amount,
    load_drainer_addresses,
    revoke_plan,
    scan,
    to_json,
    to_sarif,
)

NOW = 1749340800  # 2026-06-08
A1 = "0x" + "11" * 20
A2 = "0x" + "22" * 20
A3 = "0x" + "33" * 20


def mk(**kw) -> Approval:
    base = {"token": A1, "symbol": "TKN", "spender": A2}
    base.update(kw)
    return Approval.from_dict(base)


# --- address normalization -------------------------------------------------

def test_normalize_lowercases_and_validates():
    assert normalize_address("0x" + "AB" * 20) == "0x" + "ab" * 20
    assert normalize_address("  0x" + "cd" * 20 + "  ") == "0x" + "cd" * 20


@pytest.mark.parametrize(
    "bad",
    ["", "0x", "0x123", "not-hex", "0xZZ" + "11" * 19, "0x" + "11" * 21, None],
)
def test_normalize_rejects_bad(bad):
    with pytest.raises(ApprovalError):
        normalize_address(bad)


# --- amount parsing --------------------------------------------------------

@pytest.mark.parametrize(
    "value,expected",
    [
        ("0", 0),
        ("", 0),
        ("none", 0),
        ("null", 0),
        (None, 0),
        ("max", UINT256_MAX),
        ("unlimited", UINT256_MAX),
        ("infinite", UINT256_MAX),
        ("inf", UINT256_MAX),
        ("0x10", 16),
        ("0xff", 255),
        ("1000", 1000),
        ("1_000_000", 1000000),
        ("1,000", 1000),
        ("1.0e3", 1000),
        (12345, 12345),
    ],
)
def test_parse_amount_variants(value, expected):
    assert _parse_amount(value) == expected


def test_parse_amount_rejects_bool():
    with pytest.raises(ApprovalError):
        _parse_amount(True)


def test_parse_amount_rejects_garbage():
    with pytest.raises(ApprovalError):
        _parse_amount("twelve")


# --- classification --------------------------------------------------------

def test_classify_zero():
    assert classify_allowance(mk(amount="0")) == "zero"


def test_classify_finite():
    assert classify_allowance(mk(amount=str(10 ** 18))) == "finite"


def test_classify_infinite_uint256():
    assert classify_allowance(mk(amount=str(UINT256_MAX))) == "infinite"


def test_classify_infinite_uint96():
    assert classify_allowance(mk(amount=str(UINT96_MAX))) == "infinite"


def test_classify_effectively_infinite():
    assert classify_allowance(mk(amount=str(EFFECTIVE_INFINITE_RAW))) == "effectively_infinite"


def test_classify_blanket():
    a = mk(standard="ERC721", is_approval_for_all=True)
    assert classify_allowance(a) == "blanket"


def test_classify_just_below_eff_infinite_is_finite():
    a = mk(amount=str(EFFECTIVE_INFINITE_RAW - 1))
    assert classify_allowance(a) == "finite"


# --- scoring branches ------------------------------------------------------

def test_score_blanket_base():
    a = mk(standard="ERC1155", is_approval_for_all=True, spender_verified=True)
    f = score_approval(a, now=NOW)
    assert f.allowance_kind == "blanket"
    assert f.score >= 60
    assert any("setApprovalForAll" in r for r in f.reasons)


def test_score_infinite_verified_is_high():
    a = mk(amount="max", spender_verified=True, last_updated=NOW)
    f = score_approval(a, now=NOW)
    assert f.allowance_kind == "infinite"
    assert f.severity == "high"


def test_score_effectively_infinite_unverified():
    a = mk(amount=str(EFFECTIVE_INFINITE_RAW), spender_verified=False, last_updated=NOW)
    f = score_approval(a, now=NOW)
    assert f.allowance_kind == "effectively_infinite"
    assert any("unverified" in r for r in f.reasons)


def test_score_finite_verified_is_low():
    a = mk(amount=str(10 ** 18), spender_verified=True, last_updated=NOW)
    f = score_approval(a, now=NOW)
    assert f.severity == "low"


def test_score_zero_returns_info():
    f = score_approval(mk(amount="0"), now=NOW)
    assert f.severity == "info"
    assert f.score == 0
    assert f.reasons == ["no active allowance"]


@pytest.mark.parametrize("label", sorted(KNOWN_DRAINER_LABELS))
def test_every_drainer_label_is_critical(label):
    a = mk(amount="max", spender_label=label, spender_verified=False, last_updated=NOW)
    f = score_approval(a, now=NOW)
    assert f.severity == "critical"
    assert f.score >= 80


def test_label_substring_match():
    a = mk(amount="max", spender_label="Inferno Multi-Drainer v2", last_updated=NOW)
    f = score_approval(a, now=NOW)
    assert f.severity == "critical"


def test_clean_label_not_flagged():
    a = mk(amount=str(10 ** 18), spender_label="Uniswap V3 Router", spender_verified=True, last_updated=NOW)
    f = score_approval(a, now=NOW)
    assert not any("malicious" in r for r in f.reasons)


# --- staleness -------------------------------------------------------------

def test_stale_over_year_adds_points():
    old = NOW - 400 * 86400
    a = mk(amount="max", last_updated=old)
    f = score_approval(a, now=NOW)
    assert any("stale" in r.lower() for r in f.reasons)


def test_aging_over_180d():
    old = NOW - 200 * 86400
    a = mk(amount="max", last_updated=old)
    f = score_approval(a, now=NOW)
    assert any("aging" in r.lower() for r in f.reasons)


def test_recent_no_stale_reason():
    a = mk(amount="max", last_updated=NOW - 10 * 86400)
    f = score_approval(a, now=NOW)
    assert not any("stale" in r.lower() or "aging" in r.lower() for r in f.reasons)


def test_missing_last_updated_ok():
    a = mk(amount="max", last_updated=None)
    f = score_approval(a, now=NOW)
    assert f.severity in ("high", "critical")


# --- address denylist ------------------------------------------------------

def test_denylist_escalates_finite_to_critical():
    a = mk(amount=str(10 ** 18), spender=A2, spender_verified=True, last_updated=NOW)
    dl = load_drainer_addresses([A2])
    f = score_approval(a, now=NOW, denylist=dl)
    assert f.severity == "critical"
    assert any("deny-list" in r for r in f.reasons)


def test_denylist_normalizes_and_skips_bad():
    dl = load_drainer_addresses(["0x" + "AB" * 20, "garbage", ""])
    assert dl == {"0x" + "ab" * 20}


def test_denylist_no_match_unchanged():
    a = mk(amount=str(10 ** 18), spender=A2, spender_verified=True, last_updated=NOW)
    dl = load_drainer_addresses([A3])
    f = score_approval(a, now=NOW, denylist=dl)
    assert f.severity == "low"


# --- from_dict coercions ---------------------------------------------------

def test_from_dict_bool_string_afa():
    a = Approval.from_dict({"token": A1, "spender": A2, "approval_for_all": "yes"})
    assert a.is_approval_for_all is True


def test_from_dict_verified_string_false():
    a = Approval.from_dict({"token": A1, "spender": A2, "amount": "1", "spender_verified": "false"})
    assert a.spender_verified is False


def test_from_dict_alias_keys():
    a = Approval.from_dict({"contract": A1, "spender": A2, "allowance": "5", "label": "x"})
    assert a.token == A1
    assert a.amount == 5
    assert a.spender_label == "x"


def test_from_dict_rejects_non_object():
    with pytest.raises(ApprovalError):
        Approval.from_dict(["not", "a", "dict"])


def test_from_dict_last_updated_float_string():
    a = Approval.from_dict({"token": A1, "spender": A2, "amount": "1", "last_updated": "1700000000.0"})
    assert a.last_updated == 1700000000


# --- aggregate audit -------------------------------------------------------

def _multi():
    return load_approvals_from_text(json.dumps({
        "approvals": [
            {"token": A1, "symbol": "USDC", "spender": A2, "amount": "max", "last_updated": NOW},
            {"token": A3, "symbol": "BAYC", "spender": "0x" + "44" * 20, "standard": "ERC721",
             "is_approval_for_all": True, "spender_label": "Pink-Drainer", "spender_verified": False},
            {"token": "0x" + "55" * 20, "symbol": "Z", "spender": "0x" + "66" * 20, "amount": "0"},
            {"token": "0x" + "77" * 20, "symbol": "OK", "spender": "0x" + "88" * 20,
             "amount": str(10 ** 18), "spender_verified": True, "last_updated": NOW},
        ]
    }))


def test_audit_counts():
    r = audit_approvals(_multi(), now=NOW)
    assert r["total_approvals"] == 4
    assert r["active_approvals"] == 3  # zero dropped
    assert r["infinite_approvals"] == 2  # USDC infinite + BAYC blanket
    assert r["clean"] is False


def test_audit_risk_level_critical():
    r = audit_approvals(_multi(), now=NOW)
    assert r["risk_level"] == "critical"
    assert r["risk_score"] >= 80


def test_audit_findings_sorted():
    r = audit_approvals(_multi(), now=NOW)
    scores = [f["score"] for f in r["findings"]]
    assert scores == sorted(scores, reverse=True)
    assert r["findings"][0]["token_symbol"] == "BAYC"


def test_audit_severity_counts_sum():
    r = audit_approvals(_multi(), now=NOW)
    total = sum(r["severity_counts"][k] for k in ("critical", "high", "medium", "low", "info"))
    assert total == r["active_approvals"]


def test_audit_empty_is_clean():
    r = audit_approvals([], now=NOW)
    assert r["clean"] is True
    assert r["risk_level"] == "clean"
    assert r["risk_score"] == 0
    assert r["findings"] == []


def test_audit_with_denylist_param():
    approvals = load_approvals_from_text(json.dumps([
        {"token": A1, "symbol": "X", "spender": A2, "amount": str(10 ** 18),
         "spender_verified": True, "last_updated": NOW},
    ]))
    r = audit_approvals(approvals, now=NOW, denylist={A2})
    assert r["risk_level"] == "critical"


# --- CSV parsing -----------------------------------------------------------

def test_csv_basic():
    csv_text = (
        "token,symbol,spender,amount,spender_verified\n"
        f"{A1},FOO,{A2},max,false\n"
    )
    a = load_approvals_from_text(csv_text, fmt="csv")
    assert len(a) == 1
    assert a[0].amount == UINT256_MAX
    assert a[0].spender_verified is False


def test_csv_multiple_rows():
    csv_text = (
        "token,symbol,spender,amount\n"
        f"{A1},A,{A2},0\n"
        f"{A3},B,0x{'99'*20},max\n"
    )
    a = load_approvals_from_text(csv_text, fmt="csv")
    assert len(a) == 2
    assert a[0].amount == 0
    assert a[1].amount == UINT256_MAX


def test_auto_detects_json():
    a = load_approvals_from_text(json.dumps([{"token": A1, "spender": A2, "amount": "5"}]))
    assert a[0].amount == 5


def test_single_object_coerced():
    a = load_approvals_from_text(json.dumps({"token": A1, "spender": A2, "amount": "5"}))
    assert len(a) == 1


def test_record_error_index_reported():
    text = json.dumps([{"token": A1, "spender": A2, "amount": "1"}, {"token": "bad", "spender": A2}])
    with pytest.raises(ApprovalError) as exc:
        load_approvals_from_text(text)
    assert "record 1" in str(exc.value)


# --- scan() / to_json ------------------------------------------------------

def test_scan_loads_file(tmp_path):
    p = tmp_path / "approvals.json"
    p.write_text(json.dumps([{"token": A1, "symbol": "X", "spender": A2, "amount": "max", "last_updated": NOW}]))
    r = scan(str(p), now=NOW)
    assert r["tool"] == "approvewarden"
    assert r["active_approvals"] == 1


def test_to_json_roundtrip():
    r = audit_approvals(_multi(), now=NOW)
    parsed = json.loads(to_json(r))
    assert parsed["risk_level"] == r["risk_level"]


# --- revoke plan -----------------------------------------------------------

def test_revoke_plan_high_default():
    r = audit_approvals(_multi(), now=NOW)
    plan = revoke_plan(r)
    assert len(plan) >= 1
    calls = {p["call"] for p in plan}
    # BAYC blanket -> setApprovalForAll(... , false)
    assert any("setApprovalForAll" in c and "false" in c for c in calls)
    # USDC infinite -> approve(spender, 0)
    assert any(c.startswith("approve(") and c.endswith(", 0)") for c in calls)


def test_revoke_plan_advisory_note():
    r = audit_approvals(_multi(), now=NOW)
    for p in revoke_plan(r):
        assert "advisory" in p["note"]


def test_revoke_plan_threshold_filters():
    r = audit_approvals(_multi(), now=NOW)
    crit = revoke_plan(r, min_severity="critical")
    high = revoke_plan(r, min_severity="high")
    assert len(crit) <= len(high)


def test_revoke_plan_clean_empty():
    r = audit_approvals([], now=NOW)
    assert revoke_plan(r) == []


# --- SARIF -----------------------------------------------------------------

def test_sarif_structure():
    r = audit_approvals(_multi(), now=NOW)
    s = to_sarif(r, source_file="x.json")
    assert s["version"] == "2.1.0"
    assert s["runs"][0]["tool"]["driver"]["name"] == "approvewarden"
    assert len(s["runs"][0]["results"]) == r["active_approvals"]


def test_sarif_levels_mapped():
    r = audit_approvals(_multi(), now=NOW)
    s = to_sarif(r)
    levels = {res["level"] for res in s["runs"][0]["results"]}
    assert levels <= {"error", "warning", "note"}


def test_sarif_critical_is_error():
    r = audit_approvals(_multi(), now=NOW)
    s = to_sarif(r)
    crit = [res for res in s["runs"][0]["results"] if res["properties"]["severity"] == "critical"]
    assert crit and all(res["level"] == "error" for res in crit)


def test_sarif_rules_unique():
    r = audit_approvals(_multi(), now=NOW)
    s = to_sarif(r)
    rules = s["runs"][0]["tool"]["driver"]["rules"]
    ids = [rule["id"] for rule in rules]
    assert len(ids) == len(set(ids))
