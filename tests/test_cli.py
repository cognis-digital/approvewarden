"""CLI surface tests for APPROVEWARDEN. Offline; uses local fixtures + stdin."""
from __future__ import annotations

import io
import json
import os

import pytest

from approvewarden.cli import main

ROOT = os.path.dirname(os.path.dirname(__file__))
DEMO = os.path.join(ROOT, "demos", "01-basic", "approvals.json")
A1 = "0x" + "11" * 20
A2 = "0x" + "22" * 20


def test_no_command_prints_help_returns_1(capsys):
    assert main([]) == 1
    assert "usage" in capsys.readouterr().out.lower()


def test_scan_table_default(capsys):
    rc = main(["scan", DEMO])
    out = capsys.readouterr().out
    assert rc == 2  # critical findings trip --fail-on high
    assert "APPROVEWARDEN" in out
    assert "CRITICAL" in out


def test_scan_json(capsys):
    rc = main(["scan", DEMO, "--format", "json"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["tool"] == "approvewarden"
    assert payload["risk_level"] == "critical"
    assert rc == 2


def test_scan_sarif(capsys):
    main(["scan", DEMO, "--format", "sarif"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "approvewarden"
    assert len(payload["runs"][0]["results"]) == 5


def test_emit_revoke_table(capsys):
    main(["scan", DEMO, "--emit-revoke"])
    out = capsys.readouterr().out
    assert "revoke plan" in out.lower()
    assert "setApprovalForAll" in out or "approve(" in out


def test_emit_revoke_json(capsys):
    main(["scan", DEMO, "--emit-revoke", "--format", "json"])
    plan = json.loads(capsys.readouterr().out)
    assert isinstance(plan, list)
    assert all("call" in p for p in plan)


def test_emit_revoke_min_critical(capsys):
    main(["scan", DEMO, "--emit-revoke", "--revoke-min", "critical", "--format", "json"])
    plan = json.loads(capsys.readouterr().out)
    assert all(p["severity"] == "critical" for p in plan)


def test_fail_on_critical_only(capsys):
    # demo has criticals, so even --fail-on critical trips
    rc = main(["scan", DEMO, "--fail-on", "critical"])
    capsys.readouterr()
    assert rc == 2


def test_clean_wallet_exit_zero(tmp_path, capsys):
    p = tmp_path / "clean.json"
    p.write_text(json.dumps([{"token": A1, "symbol": "OK", "spender": A2, "amount": "0"}]))
    rc = main(["scan", str(p)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "clean" in out.lower()


def test_low_only_below_high_threshold(tmp_path, capsys):
    p = tmp_path / "low.json"
    p.write_text(json.dumps([
        {"token": A1, "symbol": "OK", "spender": A2, "amount": "1000000000000000000",
         "spender_verified": True, "last_updated": 1749340800},
    ]))
    rc = main(["scan", str(p), "--fail-on", "high"])
    capsys.readouterr()
    assert rc == 0  # low < high


def test_drainer_list_escalates(tmp_path, capsys):
    appr = tmp_path / "a.json"
    appr.write_text(json.dumps([
        {"token": A1, "symbol": "X", "spender": A2, "amount": "1000000000000000000",
         "spender_verified": True, "last_updated": 1749340800},
    ]))
    dl = tmp_path / "drainers.txt"
    dl.write_text(f"# known drainers\n{A2}\n")
    rc = main(["scan", str(appr), "--drainer-list", str(dl), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["risk_level"] == "critical"
    assert rc == 2


def test_bad_file_returns_1(capsys):
    rc = main(["scan", "/nonexistent/path/approvals.json"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "cannot read" in err.lower()


def test_bad_json_returns_1(tmp_path, capsys):
    p = tmp_path / "bad.json"
    p.write_text("{ this is not json")
    rc = main(["scan", str(p)])
    err = capsys.readouterr().err
    assert rc == 1
    assert "failed to parse" in err.lower()


def test_stdin_json(monkeypatch, capsys):
    payload = json.dumps([
        {"token": A1, "symbol": "X", "spender": A2, "amount": "max", "last_updated": 1749340800},
    ])
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    rc = main(["scan", "-", "--format", "json"])
    out = json.loads(capsys.readouterr().out)
    assert out["active_approvals"] == 1
    assert rc == 2


def test_csv_input(tmp_path, capsys):
    p = tmp_path / "a.csv"
    p.write_text("token,symbol,spender,amount,spender_verified\n" + f"{A1},FOO,{A2},max,false\n")
    rc = main(["scan", str(p), "--format", "json"])
    out = json.loads(capsys.readouterr().out)
    assert out["active_approvals"] == 1
    assert out["findings"][0]["allowance_kind"] == "infinite"
    assert rc == 2


def test_mcp_subcommand_dispatches(monkeypatch):
    called = {}

    def fake_serve():
        called["yes"] = True
        return 0

    monkeypatch.setattr("approvewarden.mcp_server.serve", fake_serve)
    rc = main(["mcp"])
    assert rc == 0
    assert called.get("yes") is True


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "approvewarden" in capsys.readouterr().out
