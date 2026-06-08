"""Smoke tests for SHIPCHECK. No network. Standard library only."""
import io
import json
import os
import sys
import unittest
import contextlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shipcheck import lint_text, TOOL_NAME, TOOL_VERSION  # noqa: E402
from shipcheck.cli import main  # noqa: E402
from shipcheck.core import _split_base  # noqa: E402


class TestParsing(unittest.TestCase):
    def test_continuation_merge(self):
        text = "FROM python:3.11-slim\nRUN apt-get update && \\\n    apt-get install -y --no-install-recommends curl && \\\n    rm -rf /var/lib/apt/lists/*\nUSER app\n"
        report = lint_text(text)
        # Combined RUN should NOT trigger the stale-cache rule.
        codes = {f.code for f in report.findings}
        self.assertNotIn("SC201", codes)
        self.assertEqual(report.instructions, 3)

    def test_split_base(self):
        self.assertEqual(_split_base("node:12"), ("node", "12"))
        self.assertEqual(_split_base("python:3.11-slim AS build"), ("python", "3.11-slim"))
        self.assertEqual(_split_base("registry.io:5000/team/app:1.2"), ("app", "1.2"))
        self.assertEqual(_split_base("ubuntu"), ("ubuntu", None))


class TestRules(unittest.TestCase):
    def test_eol_cve_critical(self):
        report = lint_text("FROM node:12\nUSER app\nCMD [\"node\"]\n")
        codes = {f.code for f in report.findings}
        self.assertIn("SC120", codes)
        self.assertEqual(report.max_severity, "critical")

    def test_unpinned_tag(self):
        report = lint_text("FROM ubuntu\nUSER app\n")
        self.assertIn("SC101", {f.code for f in report.findings})

    def test_root_user_flagged(self):
        report = lint_text("FROM python:3.11-slim\nCMD [\"x\"]\n")
        self.assertIn("SC300", {f.code for f in report.findings})

    def test_root_dropped_ok(self):
        report = lint_text("FROM python:3.11-slim\nUSER app\nCMD [\"x\"]\n")
        self.assertNotIn("SC300", {f.code for f in report.findings})

    def test_secret_detection(self):
        report = lint_text("FROM alpine:3.19\nRUN export AWS_SECRET=abc123def && build\nUSER app\n")
        finding = [f for f in report.findings if f.code == "SC230"]
        self.assertTrue(finding)
        self.assertEqual(finding[0].severity, "critical")

    def test_curl_pipe_sh(self):
        report = lint_text("FROM alpine:3.19\nRUN curl https://x.sh | sh\nUSER app\n")
        self.assertIn("SC221", {f.code for f in report.findings})

    def test_add_vs_copy(self):
        report = lint_text("FROM alpine:3.19\nADD ./src /app\nUSER app\n")
        self.assertIn("SC240", {f.code for f in report.findings})
        # A real URL ADD should not be flagged as SC240.
        report2 = lint_text("FROM alpine:3.19\nADD https://x/y.bin /app/y\nUSER app\n")
        self.assertNotIn("SC240", {f.code for f in report2.findings})

    def test_clean_dockerfile(self):
        text = (
            "FROM python:3.11-slim\n"
            "COPY requirements.txt .\n"
            "RUN pip install --no-cache-dir -r requirements.txt\n"
            "COPY app/ ./app/\n"
            "USER nobody\n"
            "CMD [\"python\", \"-m\", \"app\"]\n"
        )
        report = lint_text(text)
        # No high/critical findings expected.
        high = [f for f in report.findings if f.severity in ("high", "critical")]
        self.assertEqual(high, [], msg=str([f.to_dict() for f in high]))


class TestCLI(unittest.TestCase):
    def _write(self, tmpdir, content):
        path = os.path.join(tmpdir, "Dockerfile")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return path

    def test_json_output_and_exit(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = self._write(d, "FROM node:12\nCMD [\"node\"]\n")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["lint", path, "--format", "json"])
            self.assertEqual(rc, 1)  # critical >= medium threshold
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["tool"], TOOL_NAME)
            self.assertEqual(payload["version"], TOOL_VERSION)
            self.assertEqual(len(payload["reports"]), 1)
            self.assertEqual(payload["reports"][0]["max_severity"], "critical")

    def test_clean_exit_zero(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = self._write(
                d,
                "FROM python:3.11-slim\n"
                "COPY requirements.txt .\n"
                "RUN pip install --no-cache-dir -r requirements.txt\n"
                "USER nobody\n"
                "CMD [\"python\"]\n",
            )
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["lint", path, "--format", "json", "--fail-on", "high"])
            self.assertEqual(rc, 0)

    def test_missing_file_exit_two(self):
        buf = io.StringIO()
        err = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            rc = main(["lint", "/no/such/Dockerfile", "--format", "json"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
