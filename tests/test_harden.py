"""Hardening tests — edge cases, bad input, and error paths added during hardening."""
from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shipcheck.core import lint_text, lint_file  # noqa: E402
from shipcheck.cli import main  # noqa: E402


class TestEmptyInput(unittest.TestCase):
    """lint_text with empty / whitespace-only content must not crash."""

    def test_empty_string(self):
        report = lint_text("")
        self.assertEqual(report.findings, [])
        self.assertEqual(report.stages, 0)
        self.assertEqual(report.instructions, 0)
        self.assertIsNone(report.max_severity)

    def test_whitespace_only(self):
        report = lint_text("   \n\t\n")
        self.assertEqual(report.findings, [])

    def test_comments_only(self):
        report = lint_text("# syntax=docker/dockerfile:1\n# no instructions here\n")
        self.assertEqual(report.findings, [])
        self.assertEqual(report.stages, 0)


class TestLintTextTypeGuard(unittest.TestCase):
    """lint_text must reject non-string input with TypeError."""

    def test_rejects_none(self):
        with self.assertRaises(TypeError):
            lint_text(None)  # type: ignore[arg-type]

    def test_rejects_bytes(self):
        with self.assertRaises(TypeError):
            lint_text(b"FROM ubuntu\n")  # type: ignore[arg-type]


class TestLintFileBinary(unittest.TestCase):
    """lint_file must raise ValueError for binary (non-UTF-8) files."""

    def test_binary_file_raises_value_error(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".Dockerfile") as f:
            f.write(b"\xff\xfe binary garbage \x00\x01\x02")
            name = f.name
        try:
            with self.assertRaises(ValueError) as ctx:
                lint_file(name)
            self.assertIn("UTF-8", str(ctx.exception))
        finally:
            os.unlink(name)


class TestCLIBinaryFileExitTwo(unittest.TestCase):
    """CLI must exit 2 and print to stderr when a file cannot be decoded."""

    def test_binary_file_exit_two(self):
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=".Dockerfile"
        ) as f:
            f.write(b"\xff\xfe not utf8 \x00\xff")
            name = f.name
        try:
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc = main(["lint", name])
            self.assertEqual(rc, 2)
            self.assertIn("error", err.getvalue().lower())
        finally:
            os.unlink(name)


class TestCLIMultiplePathsPartialError(unittest.TestCase):
    """When one path is bad and another is good, exit 2 but still report
    the good one in JSON output."""

    def test_mixed_paths(self):
        with tempfile.TemporaryDirectory() as d:
            good = os.path.join(d, "Dockerfile")
            with open(good, "w", encoding="utf-8") as fh:
                fh.write(
                    "FROM python:3.11-slim\n"
                    "USER nobody\n"
                    "CMD [\"python\"]\n"
                )
            buf = io.StringIO()
            err = io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
                rc = main(["lint", good, "/no/such/path", "--format", "json"])
            self.assertEqual(rc, 2)
            # The good report should still appear in stdout JSON
            import json
            payload = json.loads(buf.getvalue())
            self.assertEqual(len(payload["reports"]), 1)


class TestReportCounts(unittest.TestCase):
    """counts() must always return all severity keys, even when zero."""

    def test_all_severities_present(self):
        report = lint_text("FROM python:3.11-slim\nUSER nobody\nCMD [\"x\"]\n")
        counts = report.counts()
        for sev in ("info", "low", "medium", "high", "critical"):
            self.assertIn(sev, counts)

    def test_to_dict_structure(self):
        report = lint_text("FROM ubuntu\nUSER nobody\n")
        d = report.to_dict()
        expected_keys = ("path", "stages", "instructions",
                         "max_severity", "counts", "findings")
        for key in expected_keys:
            self.assertIn(key, d)


class TestFindingToDict(unittest.TestCase):
    """Finding.to_dict() must be JSON-serialisable."""

    def test_serialisable(self):
        import json
        report = lint_text("FROM node:12\nCMD [\"node\"]\n")
        # Should not raise
        blob = json.dumps(report.to_dict())
        self.assertIn("SC120", blob)


if __name__ == "__main__":
    unittest.main()
