"""SHIPCHECK — Dockerfile linter with image-size and CVE advisories."""
from shipcheck.core import scan, TOOL_NAME, TOOL_VERSION
__all__ = ["scan", "TOOL_NAME", "TOOL_VERSION"]
