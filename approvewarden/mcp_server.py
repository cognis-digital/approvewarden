"""APPROVEWARDEN MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json
import sys

from approvewarden.core import ApprovalError, audit_approvals, load_approvals_from_text


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-approvewarden[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-approvewarden[mcp]'")
        return 1
    app = FastMCP("approvewarden")

    @app.tool()
    def approvewarden_scan(approvals_json: str) -> str:
        """Scans a wallet's token approvals for dangerous ERC-20/721/1155 allowances
        and scores drainer exposure. Pass a JSON string (list or object with
        'approvals' key). Returns JSON findings."""
        try:
            approvals = load_approvals_from_text(approvals_json, fmt="json")
        except (ApprovalError, ValueError) as exc:
            return json.dumps({"error": str(exc)})
        report = audit_approvals(approvals)
        return json.dumps(report, indent=2)

    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(serve())
