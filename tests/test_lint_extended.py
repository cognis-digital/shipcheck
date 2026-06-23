"""Extended coverage for the Dockerfile linter rules and parser.

All offline, standard library only. Exercises every SC-code and the public
API surface (lint_text/lint_file/scan/to_json, version resolution).
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shipcheck import TOOL_NAME, TOOL_VERSION  # noqa: E402
from shipcheck.core import (  # noqa: E402
    lint_text, lint_file, scan, to_json, Report, Finding,
    _split_base, _parse, SEVERITIES, _SEV_RANK,
)


def codes(report):
    return {f.code for f in report.findings}


class TestIdentity(unittest.TestCase):
    def test_tool_name(self):
        self.assertEqual(TOOL_NAME, "shipcheck")

    def test_version_from_file(self):
        # The VERSION file is 0.6.x — version must NOT silently fall back to 0.1.0
        self.assertNotEqual(TOOL_VERSION, "0.1.0")
        self.assertRegex(TOOL_VERSION, r"^\d+\.\d+")


class TestParser(unittest.TestCase):
    def test_comments_skipped(self):
        instrs = _parse("# a comment\nFROM alpine:3.19\n")
        self.assertEqual(len(instrs), 1)
        self.assertEqual(instrs[0].cmd, "FROM")

    def test_blank_lines_skipped(self):
        self.assertEqual(len(_parse("\n\nFROM alpine:3.19\n\n")), 1)

    def test_line_numbers(self):
        instrs = _parse("# c\nFROM alpine:3.19\nUSER app\n")
        self.assertEqual(instrs[0].line, 2)
        self.assertEqual(instrs[1].line, 3)

    def test_multi_continuation(self):
        text = "RUN a && \\\n b && \\\n c\n"
        instrs = _parse(text)
        self.assertEqual(len(instrs), 1)
        self.assertIn("c", instrs[0].args)

    def test_lowercase_directive_uppercased(self):
        self.assertEqual(_parse("from alpine:3.19\n")[0].cmd, "FROM")


class TestSplitBase(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(_split_base("alpine:3.19"), ("alpine", "3.19"))

    def test_no_tag(self):
        self.assertEqual(_split_base("alpine"), ("alpine", None))

    def test_digest_stripped(self):
        img, tag = _split_base("alpine@sha256:abc")
        self.assertEqual(img, "alpine")
        self.assertIsNone(tag)

    def test_registry_namespace(self):
        self.assertEqual(_split_base("ghcr.io/org/app:1.0"), ("app", "1.0"))

    def test_registry_port_not_tag(self):
        self.assertEqual(_split_base("registry:5000/app"), ("app", None))

    def test_as_stage_case_insensitive(self):
        self.assertEqual(_split_base("node:18 as builder"), ("node", "18"))


class TestEachRule(unittest.TestCase):
    def test_sc101_unpinned(self):
        self.assertIn("SC101", codes(lint_text("FROM ubuntu\nUSER a\n")))

    def test_sc101_latest(self):
        self.assertIn("SC101", codes(lint_text("FROM ubuntu:latest\nUSER a\n")))

    def test_sc110_heavy_base(self):
        self.assertIn("SC110", codes(lint_text("FROM ubuntu:22.04\nUSER a\n")))

    def test_sc110_suppressed_by_slim(self):
        self.assertNotIn("SC110", codes(lint_text("FROM python:3.11-slim\nUSER a\n")))

    def test_sc120_eol(self):
        self.assertIn("SC120", codes(lint_text("FROM debian:9\nUSER a\n")))

    def test_sc201_apt_update_alone(self):
        self.assertIn("SC201", codes(lint_text("FROM debian:12\nRUN apt-get update\nUSER a\n")))

    def test_sc202_no_recommends(self):
        self.assertIn("SC202", codes(lint_text("FROM debian:12\nRUN apt-get install -y curl\nUSER a\n")))

    def test_sc203_no_cache_cleanup(self):
        self.assertIn("SC203", codes(lint_text("FROM debian:12\nRUN apt-get install -y curl\nUSER a\n")))

    def test_sc210_pip_no_cache(self):
        self.assertIn("SC210", codes(lint_text("FROM python:3.11-slim\nRUN pip install flask\nUSER a\n")))

    def test_sc220_sudo(self):
        self.assertIn("SC220", codes(lint_text("FROM debian:12\nRUN sudo apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*\nUSER a\n")))

    def test_sc221_curl_pipe(self):
        self.assertIn("SC221", codes(lint_text("FROM alpine:3.19\nRUN wget -O- https://x | bash\nUSER a\n")))

    def test_sc230_secret(self):
        self.assertIn("SC230", codes(lint_text("FROM alpine:3.19\nRUN API_KEY=deadbeef ./run\nUSER a\n")))

    def test_sc240_add_plain(self):
        self.assertIn("SC240", codes(lint_text("FROM alpine:3.19\nADD ./x /x\nUSER a\n")))

    def test_sc240_not_for_url(self):
        self.assertNotIn("SC240", codes(lint_text("FROM alpine:3.19\nADD https://x/y /y\nUSER a\n")))

    def test_sc240_not_for_tar(self):
        self.assertNotIn("SC240", codes(lint_text("FROM alpine:3.19\nADD app.tar.gz /app\nUSER a\n")))

    def test_sc250_copy_dot(self):
        self.assertIn("SC250", codes(lint_text("FROM python:3.11-slim\nCOPY . .\nUSER a\n")))

    def test_sc260_ssh_port(self):
        self.assertIn("SC260", codes(lint_text("FROM alpine:3.19\nEXPOSE 22\nUSER a\n")))

    def test_sc300_root(self):
        self.assertIn("SC300", codes(lint_text("FROM alpine:3.19\nCMD x\n")))

    def test_sc300_suppressed(self):
        self.assertNotIn("SC300", codes(lint_text("FROM alpine:3.19\nUSER app\nCMD x\n")))

    def test_sc310_layer_bloat(self):
        text = "FROM alpine:3.19\n" + "".join(f"RUN echo {i}\n" for i in range(6)) + "USER a\n"
        self.assertIn("SC310", codes(lint_text(text)))

    def test_user_root_explicit_resets(self):
        # explicit USER root after a non-root USER must re-flag SC300
        self.assertIn("SC300", codes(lint_text("FROM alpine:3.19\nUSER app\nUSER root\nCMD x\n")))


class TestMultiStage(unittest.TestCase):
    def test_stage_count(self):
        text = "FROM golang:1.21 AS build\nRUN go build\nFROM alpine:3.19\nUSER app\n"
        r = lint_text(text)
        self.assertEqual(r.stages, 2)

    def test_new_stage_resets_user(self):
        text = "FROM golang:1.21 AS build\nUSER app\nFROM alpine:3.19\nCMD x\n"
        # second stage never drops root -> SC300
        self.assertIn("SC300", codes(lint_text(text)))


class TestReportModel(unittest.TestCase):
    def test_severities_ordered(self):
        self.assertEqual(SEVERITIES[-1], "critical")
        self.assertEqual(_SEV_RANK["critical"], 4)

    def test_counts_sum(self):
        r = lint_text("FROM node:12\nRUN apt-get update\nCMD x\n")
        self.assertEqual(sum(r.counts().values()), len(r.findings))

    def test_max_severity_none_when_clean(self):
        r = Report(path="x")
        self.assertIsNone(r.max_severity)

    def test_to_dict_keys(self):
        d = lint_text("FROM node:12\nUSER a\n").to_dict()
        for k in ("path", "stages", "instructions", "max_severity", "counts", "findings"):
            self.assertIn(k, d)

    def test_finding_to_dict(self):
        f = Finding(code="X", severity="low", line=1, instruction="RUN", message="m")
        self.assertEqual(f.to_dict()["code"], "X")

    def test_findings_sorted_by_line(self):
        r = lint_text("FROM node:12\nRUN apt-get update\nUSER root\nCMD x\n")
        lines = [f.line for f in r.findings]
        self.assertEqual(lines, sorted(lines))


class TestPublicApi(unittest.TestCase):
    def test_lint_file_and_scan_agree(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "Dockerfile")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("FROM node:12\nUSER a\n")
            self.assertEqual(
                {f.code for f in lint_file(p).findings},
                {f.code for f in scan(p).findings},
            )

    def test_to_json_roundtrip(self):
        r = lint_text("FROM node:12\nUSER a\n")
        payload = json.loads(to_json(r))
        self.assertIn("findings", payload)

    def test_to_json_accepts_dict(self):
        self.assertEqual(json.loads(to_json({"a": 1}))["a"], 1)


class TestCleanDockerfile(unittest.TestCase):
    def test_well_formed_no_high(self):
        text = (
            "FROM python:3.11-slim\n"
            "COPY requirements.txt .\n"
            "RUN pip install --no-cache-dir -r requirements.txt\n"
            "COPY app/ ./app/\n"
            "USER nobody\n"
            'CMD ["python", "-m", "app"]\n'
        )
        r = lint_text(text)
        self.assertEqual([f for f in r.findings if f.severity in ("high", "critical")], [])


if __name__ == "__main__":
    unittest.main()
