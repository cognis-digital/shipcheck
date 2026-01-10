"""SHIPCHECK MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from shipcheck.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-shipcheck[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-shipcheck[mcp]'")
        return 1
    app = FastMCP("shipcheck")

    @app.tool()
    def shipcheck_scan(target: str) -> str:
        """Dockerfile linter with image-size and CVE advisories. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
