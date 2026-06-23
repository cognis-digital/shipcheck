"""Command-line interface for SHIPCHECK."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import lint_file, SEVERITIES, _SEV_RANK, vulnmatch_file

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

    # ---- vulnmatch: offline CVE enrichment of base-image components --------
    vm = sub.add_parser(
        "vulnmatch",
        help="match a Dockerfile's base-image + installed packages against the "
             "bundled offline OSV vulnerability DB (262k real vulns)",
    )
    vm.add_argument("paths", nargs="+", help="Dockerfile path(s)")
    vm.add_argument("--format", choices=("table", "json"), default="table")
    vm.add_argument(
        "--fail-on-vulns", action="store_true",
        help="exit non-zero if any vulnerability matches a component",
    )
    vm.add_argument("--no-color", action="store_true")

    # ---- db: query the bundled offline OSV DB directly --------------------
    db = sub.add_parser(
        "db", help="query the bundled offline OSV vulnerability database")
    db.add_argument(
        "action", choices=("count", "cve", "package", "search"),
        help="count | cve <ID> | package <name> | search <text>")
    db.add_argument("query", nargs="?", default="", help="lookup argument")
    db.add_argument("--limit", type=int, default=20)
    db.add_argument("--ecosystem", default=None,
                    help="filter package lookups by OSV ecosystem")

    # ---- feeds: edge / air-gap data-feed catalog (datafeeds.py) -----------
    fd = sub.add_parser(
        "feeds", help="list / refresh keyless intel feeds for edge & air-gap use")
    fd.add_argument("action", choices=("list",), help="feed action")
    fd.add_argument("--domain", default=None, help="filter by feed domain")
    return p


def _render_vulnmatch(result: dict, use_color: bool) -> str:
    lines: List[str] = []
    lines.append(f"SHIPCHECK {TOOL_VERSION}  {result['path']}  (offline OSV match)")
    lines.append(
        f"  components={len(result['components'])} "
        f"matches={result['match_count']}")
    lines.append("")
    if not result["matches"]:
        lines.append("  no known vulnerabilities for the discovered components.")
        return "\n".join(lines)
    for m in result["matches"]:
        cve = next((a for a in m["aliases"] if a.upper().startswith("CVE-")),
                   m["vuln_id"])
        sev = (m["severity"] or "?")
        if use_color:
            sev = _COLOR.get(_norm_sev(sev), "") + sev + _RESET
        lines.append(
            f"  {m['component']:42} {cve:20} [{sev}] ({m['source']})")
        if m["summary"]:
            lines.append(f"        {m['summary'][:96]}")
    lines.append("")
    lines.append(f"  {result['match_count']} real OSV record(s) matched · fully offline")
    return "\n".join(lines)


def _norm_sev(s: str) -> str:
    s = (s or "").lower()
    if "critical" in s:
        return "critical"
    if "high" in s:
        return "high"
    if "moderate" in s or "medium" in s:
        return "medium"
    if "low" in s:
        return "low"
    return "info"


def _cmd_vulnmatch(args) -> int:
    results = []
    had_error = False
    any_match = False
    for path in args.paths:
        try:
            res = vulnmatch_file(path)
        except FileNotFoundError:
            sys.stderr.write(f"error: file not found: {path}\n")
            had_error = True
            continue
        except OSError as exc:
            sys.stderr.write(f"error: {exc}\n")
            had_error = True
            continue
        results.append(res)
        if res["match_count"]:
            any_match = True

    if args.format == "json":
        print(json.dumps({
            "tool": TOOL_NAME, "version": TOOL_VERSION, "reports": results,
        }, indent=2))
    else:
        use_color = (not args.no_color) and sys.stdout.isatty()
        for res in results:
            print(_render_vulnmatch(res, use_color))
            print()

    if had_error:
        return 2
    if args.fail_on_vulns and any_match:
        return 1
    return 0


def _cmd_db(args) -> int:
    from .vulndb_local import VulnDB
    db = VulnDB()
    if args.action == "count":
        print(db.count())
        return 0
    if not args.query:
        sys.stderr.write(f"error: 'db {args.action}' needs an argument\n")
        return 2
    if args.action == "cve":
        hits = db.by_cve(args.query)
    elif args.action == "package":
        hits = db.by_package(args.query, ecosystem=args.ecosystem)
    else:  # search
        hits = db.search(args.query, limit=args.limit)
    hits = hits[: args.limit]
    print(json.dumps({
        "query": args.query, "action": args.action,
        "count": len(hits), "records": hits,
    }, indent=2))
    return 0 if hits else 1


def _cmd_feeds(args) -> int:
    try:
        from . import datafeeds
    except Exception as exc:  # pragma: no cover
        sys.stderr.write(f"error: datafeeds unavailable: {exc}\n")
        return 2
    feeds = datafeeds.list_feeds(domain=args.domain)
    for f in feeds:
        print(f"  {f['id']:28} {f.get('domain',''):13} {f.get('name','')}")
    print(f"\n  {len(feeds)} feed(s).  Refresh offline cache: "
          f"python -m shipcheck.datafeeds update <id>")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "vulnmatch":
        return _cmd_vulnmatch(args)
    if args.command == "db":
        return _cmd_db(args)
    if args.command == "feeds":
        return _cmd_feeds(args)
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
