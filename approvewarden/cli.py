"""Command-line interface for APPROVEWARDEN.

Examples:
    # Audit an exported approval set (JSON or CSV), human-readable table
    approvewarden scan demos/01-basic/approvals.json

    # JSON output for piping into CI / jq
    approvewarden scan approvals.csv --format json | jq .risk_score

    # Fail the build if any approval is at/above 'high' severity
    approvewarden scan approvals.json --fail-on high

Exit codes:
    0  clean (or below the --fail-on threshold)
    2  risky approvals found at/above the --fail-on threshold
    1  usage / parse error
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from approvewarden import TOOL_NAME, TOOL_VERSION
from approvewarden.core import (
    SEVERITY_ORDER,
    ApprovalError,
    audit_approvals,
    load_approvals,
    load_drainer_addresses,
    revoke_plan,
    to_sarif,
)

_SEV_GLYPH = {
    "critical": "!!",
    "high": "! ",
    "medium": "~ ",
    "low": ". ",
    "info": "  ",
}


def _short(addr: str) -> str:
    if len(addr) <= 12:
        return addr
    return f"{addr[:6]}…{addr[-4:]}"


def _render_table(report: dict) -> str:
    lines: list[str] = []
    lines.append(f"APPROVEWARDEN {TOOL_VERSION} — approval audit")
    lines.append("=" * 60)
    lines.append(
        f"Risk: {report['risk_score']}/100 ({report['risk_level'].upper()})   "
        f"active={report['active_approvals']}  "
        f"infinite/blanket={report['infinite_approvals']}"
    )
    sc = report["severity_counts"]
    lines.append(
        "Severity: "
        + "  ".join(
            f"{k}={sc[k]}" for k in ("critical", "high", "medium", "low")
        )
    )
    lines.append("-" * 60)

    findings = report["findings"]
    if not findings:
        lines.append("No active approvals found. Wallet is clean.")
        return "\n".join(lines)

    header = f"{'SEV':<4} {'SCORE':>5}  {'TOKEN':<10} {'SPENDER':<14} KIND"
    lines.append(header)
    for f in findings:
        glyph = _SEV_GLYPH.get(f["severity"], "  ")
        sym = f["token_symbol"] or _short(f["token"])
        spender = f["spender_label"] or _short(f["spender"])
        lines.append(
            f"{glyph:<4} {f['score']:>5}  {sym:<10} {spender:<14} {f['allowance_kind']}"
        )
        for r in f["reasons"]:
            lines.append(f"        - {r}")
    lines.append("-" * 60)
    lines.append(
        "Revoke infinite/blanket and malicious-spender approvals via "
        "revoke.cash or eth_call to approve(spender, 0)."
    )
    return "\n".join(lines)


def _render_revoke_plan(plan: list[dict]) -> str:
    lines: list[str] = []
    lines.append(f"APPROVEWARDEN {TOOL_VERSION} — advisory revoke plan")
    lines.append("=" * 60)
    if not plan:
        lines.append("Nothing to revoke at/above the chosen severity. ✓")
        return "\n".join(lines)
    lines.append(
        f"{len(plan)} approval(s) recommended for revocation "
        "(advisory only — sign in your own wallet):"
    )
    lines.append("-" * 60)
    for i, p in enumerate(plan, 1):
        sym = p["token_symbol"] or _short(p["token"])
        lines.append(
            f"{i:>2}. [{p['severity'].upper():<8}] {sym:<10} {p['standard']}"
        )
        lines.append(f"      token:  {p['token']}")
        lines.append(f"      call:   {p['call']}")
    lines.append("-" * 60)
    lines.append("approvewarden never signs or broadcasts — these are read-only calls.")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Scan a wallet's token approvals for infinite allowances and "
            "score drainer exposure (offline, CI-friendly)."
        ),
        epilog=(
            "examples:\n"
            "  approvewarden scan approvals.json\n"
            "  approvewarden scan approvals.csv --format json | jq .risk_score\n"
            "  approvewarden scan approvals.json --fail-on high\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}"
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser(
        "scan",
        help="audit an exported approval set (JSON or CSV)",
        description="Audit an exported approval set for risky allowances.",
    )
    scan.add_argument(
        "input",
        help="path to approvals file (.json or .csv). Use '-' for stdin (JSON).",
    )
    scan.add_argument(
        "--format",
        choices=("table", "json", "sarif"),
        default="table",
        help="output format (default: table). sarif = code-scanning dashboards.",
    )
    scan.add_argument(
        "--emit-revoke",
        action="store_true",
        help=(
            "instead of the audit, print an advisory revoke plan "
            "(approve(spender,0) / setApprovalForAll(spender,false)). "
            "Read-only: nothing is signed or broadcast."
        ),
    )
    scan.add_argument(
        "--revoke-min",
        choices=tuple(s for s in SEVERITY_ORDER if s != "info"),
        default="high",
        help="minimum severity to include in --emit-revoke (default: high)",
    )
    scan.add_argument(
        "--drainer-list",
        default=None,
        help=(
            "path to a newline-delimited file of known-drainer spender "
            "addresses; matches escalate to critical (offline deny-list)"
        ),
    )
    scan.add_argument(
        "--input-format",
        choices=("auto", "json", "csv"),
        default="auto",
        help="how to parse the input (default: auto-detect)",
    )
    scan.add_argument(
        "--fail-on",
        choices=tuple(s for s in SEVERITY_ORDER if s != "info"),
        default="high",
        help=(
            "exit non-zero (2) if any finding is at/above this severity "
            "(default: high). Use to gate CI."
        ),
    )

    sub.add_parser(
        "mcp",
        help="start the MCP stdio server (needs the [mcp] extra)",
        description="Expose approvewarden.scan() as an MCP tool over stdio.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "mcp":
        from approvewarden.mcp_server import serve

        return serve()

    if args.command != "scan":
        parser.print_help()
        return 1

    try:
        if args.input == "-":
            from approvewarden.core import load_approvals_from_text

            fmt = "json" if args.input_format == "auto" else args.input_format
            approvals = load_approvals_from_text(sys.stdin.read(), fmt=fmt)
        else:
            approvals = load_approvals(args.input, fmt=args.input_format)
    except (ApprovalError, json.JSONDecodeError) as exc:
        print(f"error: failed to parse approvals: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: cannot read input: {exc}", file=sys.stderr)
        return 1

    denylist = None
    if args.drainer_list:
        try:
            with open(args.drainer_list, "r", encoding="utf-8") as fh:
                lines = [
                    ln.strip()
                    for ln in fh
                    if ln.strip() and not ln.lstrip().startswith("#")
                ]
            denylist = load_drainer_addresses(lines)
        except OSError as exc:
            print(f"error: cannot read drainer list: {exc}", file=sys.stderr)
            return 1

    report = audit_approvals(approvals, denylist=denylist)

    if args.emit_revoke:
        plan = revoke_plan(report, min_severity=args.revoke_min)
        if args.format == "json":
            print(json.dumps(plan, indent=2))
        else:
            print(_render_revoke_plan(plan))
    elif args.format == "json":
        print(json.dumps(report, indent=2))
    elif args.format == "sarif":
        src = args.input if args.input != "-" else "approvals.json"
        print(json.dumps(to_sarif(report, source_file=src), indent=2))
    else:
        print(_render_table(report))

    threshold = SEVERITY_ORDER[args.fail_on]
    worst = 0
    for f in report["findings"]:
        worst = max(worst, SEVERITY_ORDER.get(f["severity"], 0))
    if worst >= threshold:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
