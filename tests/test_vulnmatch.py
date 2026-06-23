"""Tests for offline CVE enrichment of Docker base-image components.

All lookups hit the bundled OSV corpus (shipcheck/cognis_vulndb.jsonl.gz);
no network. Proves real CVEs (e.g. log4shell) resolve against real components.
"""
import io
import json
import os
import sys
import contextlib
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shipcheck.core import (  # noqa: E402
    extract_components, match_components, vulnmatch_text, vulnmatch_file,
    _split_install_args,
)
from shipcheck.vulndb_local import VulnDB  # noqa: E402
from shipcheck.cli import main  # noqa: E402

DB = VulnDB()  # shared, lazy-loaded once


class TestComponentExtraction(unittest.TestCase):
    def test_base_openjdk_yields_log4j(self):
        comps = extract_components("FROM openjdk:11\nCMD java\n")
        names = {p for _, p, _ in comps}
        self.assertIn("org.apache.logging.log4j:log4j-core", names)

    def test_base_python_yields_runtime_pkgs(self):
        comps = extract_components("FROM python:3.11-slim\n")
        names = {p for _, p, _ in comps}
        self.assertTrue({"pip", "setuptools", "wheel"} & names)

    def test_pip_install_extracted(self):
        comps = extract_components("FROM python:3.11-slim\nRUN pip install django==2.2.0 requests\n")
        names = {p for _, p, _ in comps}
        self.assertIn("django", names)
        self.assertIn("requests", names)

    def test_npm_install_extracted(self):
        comps = extract_components("FROM node:18\nRUN npm install lodash express\n")
        names = {p for _, p, _ in comps}
        self.assertIn("lodash", names)
        self.assertIn("express", names)

    def test_gem_install_extracted(self):
        comps = extract_components("FROM ruby:3.2\nRUN gem install rails\n")
        names = {p for _, p, _ in comps}
        self.assertIn("rails", names)

    def test_apt_install_extracted(self):
        comps = extract_components("FROM debian:12\nRUN apt-get install -y curl openssl\n")
        names = {p for _, p, _ in comps}
        self.assertIn("curl", names)
        self.assertIn("openssl", names)

    def test_dedup(self):
        comps = extract_components("FROM python:3.11\nRUN pip install requests\nRUN pip install requests\n")
        reqs = [p for _, p, _ in comps if p == "requests"]
        self.assertEqual(len(reqs), 1)

    def test_components_carry_source(self):
        comps = extract_components("FROM openjdk:11\nRUN pip install django\n")
        sources = {s for _, _, s in comps}
        self.assertIn("base:openjdk", sources)
        self.assertIn("pip-install", sources)


class TestInstallArgParsing(unittest.TestCase):
    def test_strips_flags(self):
        self.assertNotIn("-y", _split_install_args("-y --no-cache-dir requests"))

    def test_strips_version_pins(self):
        self.assertEqual(_split_install_args("django==2.2.0"), ["django"])
        self.assertEqual(_split_install_args("lodash@4.17.0"), ["lodash"])
        self.assertEqual(_split_install_args("pkg>=1.0"), ["pkg"])

    def test_drops_paths(self):
        self.assertEqual(_split_install_args("./local-wheel.whl"), [])

    def test_multiple(self):
        self.assertEqual(set(_split_install_args("a b c")), {"a", "b", "c"})


class TestRealCveResolution(unittest.TestCase):
    def test_log4shell_resolves_via_base_image(self):
        res = vulnmatch_text("FROM openjdk:11\nCMD java\n", db=DB)
        cves = set()
        for m in res["matches"]:
            cves.update(m["aliases"])
        self.assertIn("CVE-2021-44228", cves, "log4shell must resolve from openjdk base")

    def test_log4shell_record_exists_directly(self):
        hits = DB.by_cve("CVE-2021-44228")
        self.assertTrue(hits)
        self.assertIn("GHSA-jfh8-c2jp-5v3q", {h["id"] for h in hits})

    def test_django_has_vulns(self):
        res = vulnmatch_text("FROM python:3.11-slim\nRUN pip install django==2.0\n", db=DB)
        django = [m for m in res["matches"] if m["component"] == "django"]
        self.assertTrue(django, "django should match known OSV records")

    def test_match_count_is_int(self):
        res = vulnmatch_text("FROM python:3.11\nRUN pip install requests\n", db=DB)
        self.assertIsInstance(res["match_count"], int)
        self.assertEqual(res["match_count"], len(res["matches"]))

    def test_clean_image_few_or_no_matches(self):
        # scratch has no bundled components -> no matches, no fabrication
        res = vulnmatch_text("FROM scratch\nCOPY app /app\n", db=DB)
        self.assertEqual(res["match_count"], 0)

    def test_offline_flag_set(self):
        res = vulnmatch_text("FROM python:3.11\n", db=DB)
        self.assertTrue(res["offline"])

    def test_ecosystem_filtering(self):
        # a PyPI lookup must not surface npm records of the same name
        matches = match_components([("PyPI", "lodash", "test")], db=DB)
        for m in matches:
            self.assertNotEqual(m["ecosystem"].lower(), "npm")

    def test_match_fields_present(self):
        res = vulnmatch_text("FROM openjdk:11\n", db=DB)
        m = res["matches"][0]
        for k in ("component", "ecosystem", "vuln_id", "aliases", "severity", "summary", "source"):
            self.assertIn(k, m)


class TestVulnDB(unittest.TestCase):
    def test_count_262k(self):
        self.assertGreaterEqual(DB.count(), 260000)

    def test_by_package_lodash(self):
        self.assertTrue(DB.by_package("lodash"))

    def test_by_package_case_insensitive(self):
        self.assertEqual(len(DB.by_package("LODASH")), len(DB.by_package("lodash")))

    def test_by_cve_unknown_empty(self):
        self.assertEqual(DB.by_cve("CVE-0000-00000"), [])

    def test_search_returns_records(self):
        hits = DB.search("remote code execution", limit=5)
        self.assertLessEqual(len(hits), 5)

    def test_iter_records_have_keys(self):
        r = next(iter(DB))
        for k in ("id", "aliases", "ecosystem", "summary", "severity", "packages"):
            self.assertIn(k, r)

    def test_module_level_count(self):
        from shipcheck.vulndb_local import count
        self.assertGreaterEqual(count(), 260000)


class TestVulnmatchCLI(unittest.TestCase):
    def _write(self, d, content):
        p = os.path.join(d, "Dockerfile")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(content)
        return p

    def test_json_output(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, "FROM openjdk:11\nUSER app\n")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["vulnmatch", p, "--format", "json"])
            self.assertEqual(rc, 0)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["tool"], "shipcheck")
            self.assertTrue(payload["reports"][0]["match_count"] > 0)

    def test_fail_on_vulns_nonzero(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, "FROM openjdk:11\nUSER app\n")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["vulnmatch", p, "--format", "json", "--fail-on-vulns"])
            self.assertEqual(rc, 1)

    def test_fail_on_vulns_clean_zero(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, "FROM scratch\nCOPY a /a\n")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["vulnmatch", p, "--format", "json", "--fail-on-vulns"])
            self.assertEqual(rc, 0)

    def test_missing_file_exit_two(self):
        buf, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            rc = main(["vulnmatch", "/no/such/Dockerfile", "--format", "json"])
        self.assertEqual(rc, 2)

    def test_table_output_runs(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, "FROM openjdk:11\nUSER app\n")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main(["vulnmatch", p, "--no-color"])
            self.assertEqual(rc, 0)
            self.assertIn("offline OSV match", buf.getvalue())


class TestDBCLI(unittest.TestCase):
    def test_count(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["db", "count"])
        self.assertEqual(rc, 0)
        self.assertGreaterEqual(int(buf.getvalue().strip()), 260000)

    def test_cve_lookup(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["db", "cve", "CVE-2021-44228"])
        self.assertEqual(rc, 0)
        payload = json.loads(buf.getvalue())
        self.assertGreaterEqual(payload["count"], 1)

    def test_package_lookup(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["db", "package", "lodash"])
        self.assertEqual(rc, 0)
        self.assertGreaterEqual(json.loads(buf.getvalue())["count"], 1)

    def test_search(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["db", "search", "deserialization", "--limit", "3"])
        self.assertEqual(rc, 0)
        self.assertLessEqual(json.loads(buf.getvalue())["count"], 3)

    def test_unknown_cve_exit_one(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["db", "cve", "CVE-0000-00000"])
        self.assertEqual(rc, 1)

    def test_missing_arg_exit_two(self):
        buf, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            rc = main(["db", "cve"])
        self.assertEqual(rc, 2)


class TestFeedsCLI(unittest.TestCase):
    def test_list_runs(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["feeds", "list"])
        self.assertEqual(rc, 0)
        self.assertIn("feed(s)", buf.getvalue())

    def test_list_has_vuln_feeds(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main(["feeds", "list", "--domain", "vuln"])
        out = buf.getvalue()
        self.assertIn("cisa-kev", out)
        self.assertIn("osv", out)


if __name__ == "__main__":
    unittest.main()
