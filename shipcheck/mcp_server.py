"""SHIPCHECK MCP server — exposes lint() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json
import sys

from shipcheck.core import lint_file


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-shipcheck[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("Install the MCP extra: pip install 'cognis-shipcheck[mcp]'")
        return 1

    app = FastMCP("shipcheck")

    @app.tool()
    def shipcheck_scan(target: str) -> str:
        """Dockerfile linter with image-size and CVE advisories.

        Returns JSON findings for the Dockerfile at *target*.
        """
        try:
            report = lint_file(target)
        except (FileNotFoundError, ValueError, OSError) as exc:
            return json.dumps({"error": str(exc)})
        return json.dumps(report.to_dict(), indent=2)

    try:
        app.run()
    except Exception as exc:  # pragma: no cover
        print(f"MCP server error: {exc}", file=sys.stderr)
        return 1
    return 0
