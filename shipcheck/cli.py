"""Command-line interface for SHIPCHECK."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import lint_file, SEVERITIES, _SEV_RANK

_FAIL_DEFAULT = "medium"

_COLOR = {
    "critical": "\033[95m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[96m",
    "info": "\033[90m",
}
_RESET = "\033[0m"


def _render_table(report, use_color: bool) -> str:
    lines: List[str] = []
    lines.append(f"SHIPCHECK {TOOL_VERSION}  {report.path}")
    lines.append(
        f"  stages={report.stages} instructions={report.instructions} "
        f"findings={len(report.findings)}"
    )
    lines.append("")
    if not report.findings:
        lines.append("  no findings - ship it.")
        return "\n".join(lines)
    for f in report.findings:
        sev = f.severity.upper().ljust(8)
        if use_color:
            sev = _COLOR.get(f.severity, "") + sev + _RESET
        lines.append(f"  L{f.line:<4} {sev} {f.code}  {f.message}")
        if f.hint:
            lines.append(f"        -> {f.hint}")
    lines.append("")
    c = report.counts()
    summary = "  ".join(f"{s}:{c[s]}" for s in SEVERITIES if c[s])
    lines.append(f"  summary: {summary or 'clean'}  (max={report.max_severity})")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Dockerfile linter with image-size and CVE advisories.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command", required=True)

    lint = sub.add_parser("lint", help="lint one or more Dockerfiles")
    lint.add_argument("paths", nargs="+", help="Dockerfile path(s)")
    lint.add_argument("--format", choices=("table", "json"), default="table")
    lint.add_argument(
        "--fail-on", choices=SEVERITIES, default=_FAIL_DEFAULT,
        help="minimum severity that causes a non-zero exit (default: medium)",
    )
    lint.add_argument("--no-color", action="store_true",
                      help="disable ANSI colors in table output")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "lint":
        parser.error("unknown command")
        return 2

    reports = []
    worst_rank = -1
    had_error = False
    for path in args.paths:
        try:
            report = lint_file(path)
        except FileNotFoundError:
            sys.stderr.write(f"error: file not found: {path}\n")
            had_error = True
            continue
        except OSError as exc:
            sys.stderr.write(f"error: {exc}\n")
            had_error = True
            continue
        reports.append(report)
        if report.max_severity is not None:
            worst_rank = max(worst_rank, _SEV_RANK[report.max_severity])

    if args.format == "json":
        payload = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "reports": [r.to_dict() for r in reports],
        }
        print(json.dumps(payload, indent=2))
    else:
        use_color = (not args.no_color) and sys.stdout.isatty()
        for r in reports:
            print(_render_table(r, use_color))
            print()

    if had_error:
        return 2
    fail_rank = _SEV_RANK[args.fail_on]
    if worst_rank >= fail_rank:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
