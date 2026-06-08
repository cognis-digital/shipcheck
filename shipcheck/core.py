"""Core engine for SHIPCHECK.

Parses a Dockerfile (including line continuations and multi-stage builds),
then runs a battery of rules covering:
  * security hygiene (root user, ADD vs COPY, secrets, sudo, curl|sh)
  * cache/layer efficiency (apt-get update without install, missing
    --no-install-recommends, no cleanup of package caches, COPY . before deps)
  * image-size advisories (heavy base images, missing slim/alpine variants,
    multi-RUN layer bloat)
  * CVE advisories (pinned base-image tags matched against a bundled, offline
    advisory table of well-known vulnerable image tags)

No network access. The advisory data is a small, static, illustrative table.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Tuple

SEVERITIES = ("info", "low", "medium", "high", "critical")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Offline, illustrative CVE advisory table keyed by (image, tag).
# Real tools query a live DB; here we ship a static snapshot so checks are
# deterministic and need no network.
_CVE_TABLE = {
    ("debian", "8"): ["EOL: Debian 8 (jessie) is end-of-life; no security updates"],
    ("debian", "9"): ["EOL: Debian 9 (stretch) is end-of-life"],
    ("ubuntu", "16.04"): ["EOL: Ubuntu 16.04 reached end of standard support"],
    ("ubuntu", "18.04"): ["EOL: Ubuntu 18.04 reached end of standard support"],
    ("node", "10"): ["EOL: Node 10 is end-of-life; many unpatched CVEs"],
    ("node", "12"): ["EOL: Node 12 is end-of-life; many unpatched CVEs"],
    ("python", "3.6"): ["EOL: Python 3.6 is end-of-life; no security fixes"],
    ("python", "3.7"): ["EOL: Python 3.7 is end-of-life; no security fixes"],
    ("alpine", "3.9"): ["EOL: Alpine 3.9 no longer receives security updates"],
}

# Base images that pull a large general-purpose OS; slimmer variants exist.
_HEAVY_BASES = {
    "ubuntu": "consider a -slim language image or distroless/alpine base",
    "debian": "consider debian:<ver>-slim or distroless",
    "node": "consider node:<ver>-slim or node:<ver>-alpine",
    "python": "consider python:<ver>-slim",
    "openjdk": "consider an -slim or eclipse-temurin:<ver>-jre image",
}

_SLIM_HINT = re.compile(r"(slim|alpine|distroless|-jre|busybox|scratch)", re.I)


@dataclass
class Finding:
    code: str
    severity: str
    line: int
    instruction: str
    message: str
    hint: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Report:
    path: str
    findings: List[Finding] = field(default_factory=list)
    stages: int = 0
    instructions: int = 0

    @property
    def max_severity(self) -> Optional[str]:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: _SEV_RANK[f.severity]).severity

    def counts(self) -> dict:
        out = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            out[f.severity] += 1
        return out

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "stages": self.stages,
            "instructions": self.instructions,
            "max_severity": self.max_severity,
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class _Instr:
    line: int  # 1-based line of the instruction start
    cmd: str   # upper-cased directive, e.g. FROM, RUN
    args: str  # joined argument text (continuations merged)


def _parse(text: str) -> List[_Instr]:
    """Parse Dockerfile text into logical instructions, merging continuations."""
    instrs: List[_Instr] = []
    raw_lines = text.splitlines()
    i = 0
    n = len(raw_lines)
    while i < n:
        line = raw_lines[i]
        start = i + 1
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        # Merge backslash continuations.
        buf = line
        while buf.rstrip().endswith("\\") and i + 1 < n:
            buf = buf.rstrip()[:-1] + " " + raw_lines[i + 1]
            i += 1
        i += 1
        buf = buf.strip()
        parts = buf.split(None, 1)
        if not parts:
            continue
        cmd = parts[0].upper()
        args = parts[1].strip() if len(parts) > 1 else ""
        instrs.append(_Instr(line=start, cmd=cmd, args=args))
    return instrs


def _split_base(image_ref: str) -> Tuple[str, Optional[str]]:
    """Return (image, tag) from a FROM reference, stripping registry/digest."""
    ref = image_ref.strip()
    # Drop 'AS stage' if present.
    ref = re.split(r"\s+[Aa][Ss]\s+", ref)[0].strip()
    # Drop digest.
    ref = ref.split("@", 1)[0]
    # Separate tag (last colon not part of a registry port).
    name = ref
    tag = None
    if ":" in ref:
        head, maybe_tag = ref.rsplit(":", 1)
        # A registry port looks like host:5000/path -> contains '/'.
        if "/" not in maybe_tag:
            name, tag = head, maybe_tag
    # Strip registry host + namespace, keep last path component as image name.
    image = name.split("/")[-1].lower()
    return image, tag


def _add(findings, code, sev, instr, msg, hint=""):
    findings.append(
        Finding(code=code, severity=sev, line=instr.line,
                instruction=instr.cmd, message=msg, hint=hint)
    )


_SECRET_RE = re.compile(
    r"(?i)(password|passwd|secret|api[_-]?key|access[_-]?key|token|aws_secret)\s*[=:]\s*\S+"
)
_CURL_PIPE_SH = re.compile(r"(?i)\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(sh|bash)\b")


def _check(instrs: List[_Instr]) -> List[Finding]:
    findings: List[Finding] = []
    last_user_root = True  # containers default to root
    saw_from = False
    run_count = 0
    copy_dot_line: Optional[int] = None
    saw_dep_install_after_copy_dot = False

    for idx, ins in enumerate(instrs):
        cmd, args = ins.cmd, ins.args
        low = args.lower()

        if cmd == "FROM":
            saw_from = True
            last_user_root = True  # new stage resets user
            image, tag = _split_base(args)
            # SC101: unpinned / latest tag
            if tag is None:
                _add(findings, "SC101", "medium", ins,
                     f"base image '{image}' has no explicit tag (defaults to :latest)",
                     "pin a specific version for reproducible builds")
            elif tag == "latest":
                _add(findings, "SC101", "medium", ins,
                     f"base image '{image}' pinned to ':latest'",
                     "pin a specific version; ':latest' is not reproducible")
            # SC110: heavy base image
            if image in _HEAVY_BASES and not _SLIM_HINT.search(args):
                _add(findings, "SC110", "info", ins,
                     f"'{image}' is a large base image",
                     _HEAVY_BASES[image])
            # SC120: CVE / EOL advisory
            if tag is not None:
                for advisory in _CVE_TABLE.get((image, tag), []):
                    sev = "critical" if advisory.startswith("EOL") else "high"
                    _add(findings, "SC120", sev, ins,
                         f"{image}:{tag} - {advisory}",
                         "upgrade to a supported, patched tag")

        elif cmd == "USER":
            last_user_root = args.strip().lower() in ("root", "0", "")

        elif cmd == "RUN":
            run_count += 1
            # SC201: apt-get update without install in same RUN (cache staleness)
            if "apt-get update" in low and "install" not in low:
                _add(findings, "SC201", "high", ins,
                     "'apt-get update' in its own layer causes stale-cache installs",
                     "chain 'apt-get update && apt-get install' in one RUN")
            # SC202: missing --no-install-recommends
            if "apt-get install" in low and "--no-install-recommends" not in low:
                _add(findings, "SC202", "low", ins,
                     "apt-get install without --no-install-recommends",
                     "add --no-install-recommends to shrink the image")
            # SC203: no apt cache cleanup
            if "apt-get install" in low and "rm -rf /var/lib/apt/lists" not in low:
                _add(findings, "SC203", "low", ins,
                     "apt lists not removed; package cache bloats the layer",
                     "append '&& rm -rf /var/lib/apt/lists/*'")
            # SC210: pip install without --no-cache-dir
            if re.search(r"pip3?\s+install", low) and "--no-cache-dir" not in low:
                _add(findings, "SC210", "low", ins,
                     "pip install without --no-cache-dir leaves wheel cache",
                     "add --no-cache-dir")
            # SC220: sudo inside RUN
            if re.search(r"\bsudo\b", low):
                _add(findings, "SC220", "medium", ins,
                     "'sudo' used in RUN; builds run as root already",
                     "remove sudo; use USER for privilege drops")
            # SC221: curl|sh remote-exec
            if _CURL_PIPE_SH.search(args):
                _add(findings, "SC221", "high", ins,
                     "piping a downloaded script straight into a shell",
                     "download, verify a checksum, then execute")
            # SC230: secret literal in RUN
            if _SECRET_RE.search(args):
                _add(findings, "SC230", "critical", ins,
                     "possible hard-coded secret in RUN layer",
                     "use build secrets/args, never bake credentials into layers")
            if copy_dot_line is not None:
                saw_dep_install_after_copy_dot = True

        elif cmd == "ADD":
            # SC240: ADD used where COPY suffices (no URL, no tar auto-extract intent)
            first = args.split()[0] if args.split() else ""
            is_url = first.startswith(("http://", "https://"))
            is_tar = first.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz"))
            if not is_url and not is_tar:
                _add(findings, "SC240", "low", ins,
                     "ADD used for a plain file/dir",
                     "prefer COPY; ADD has surprising URL/tar semantics")

        elif cmd == "COPY":
            # SC250: COPY . . before dependency install hurts layer caching
            tokens = args.split()
            srcs = [t for t in tokens[:-1] if not t.startswith("--")] if len(tokens) >= 2 else tokens
            if any(s in (".", "./") for s in srcs) and copy_dot_line is None:
                copy_dot_line = ins.line
                copy_dot_instr = ins  # noqa: F841
                # defer the finding decision until end (need to know if deps follow)
                _pending_copy_dot = ins
                findings.append(Finding(
                    code="SC250", severity="info", line=ins.line,
                    instruction="COPY",
                    message="COPY . . early invalidates cache on any source change",
                    hint="copy dependency manifests + install first, then COPY .",
                ))

        elif cmd == "EXPOSE":
            # SC260: privileged/SSH port
            for p in re.findall(r"\d+", args):
                if p == "22":
                    _add(findings, "SC260", "medium", ins,
                         "EXPOSE 22 hints at running sshd in a container",
                         "avoid SSH in containers; use exec/attach instead")

    # SC300: never dropped from root
    if saw_from and last_user_root:
        # Attach to the last instruction for a stable line number.
        anchor = instrs[-1] if instrs else _Instr(line=1, cmd="FROM", args="")
        findings.append(Finding(
            code="SC300", severity="high", line=anchor.line,
            instruction="USER",
            message="container runs as root (no trailing USER directive)",
            hint="add a non-root 'USER' before the final CMD/ENTRYPOINT",
        ))

    # SC310: layer bloat from many separate RUN lines
    if run_count >= 5:
        anchor = instrs[-1]
        findings.append(Finding(
            code="SC310", severity="info", line=anchor.line,
            instruction="RUN",
            message=f"{run_count} separate RUN layers detected",
            hint="combine related RUN steps with '&&' to reduce layers/size",
        ))

    findings.sort(key=lambda f: (f.line, -_SEV_RANK[f.severity]))
    return findings


def lint_text(text: str, path: str = "<text>") -> Report:
    instrs = _parse(text)
    stages = sum(1 for i in instrs if i.cmd == "FROM")
    report = Report(path=path, stages=stages, instructions=len(instrs))
    report.findings = _check(instrs)
    return report


def lint_file(path: str) -> Report:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    return lint_text(text, path=path)
