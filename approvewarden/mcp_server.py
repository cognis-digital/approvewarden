"""APPROVEWARDEN MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from approvewarden.core import scan, to_json

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
    def approvewarden_scan(target: str) -> str:
        """Scans any wallet for dangerous ERC-20/721/1155 token approvals and infinite allowances, scoring drainer exposure and emitting revoke transactions.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
