"""SHIPCHECK - a Dockerfile linter with image-size and CVE advisories.

Standard-library only. Zero install. Spirit of hadolint + dive.
"""
from .core import (
    Finding,
    Report,
    lint_text,
    lint_file,
    SEVERITIES,
)

TOOL_NAME = "shipcheck"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Finding",
    "Report",
    "lint_text",
    "lint_file",
    "SEVERITIES",
    "TOOL_NAME",
    "TOOL_VERSION",
]
