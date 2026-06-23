"""Offline tests for the edge/air-gap data-feed catalog (shipcheck.datafeeds).

No network: only catalog parsing, cache freshness math, offline-serve behavior,
and the sneakernet snapshot export/import roundtrip are exercised.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shipcheck import datafeeds  # noqa: E402


class TestCatalog(unittest.TestCase):
    def test_catalog_loads(self):
        cat = datafeeds.load_catalog()
        self.assertIn("feeds", cat)
        self.assertGreaterEqual(len(cat["feeds"]), 20)

    def test_every_feed_has_required_fields(self):
        for f in datafeeds.load_catalog()["feeds"]:
            self.assertIn("id", f)
            self.assertIn("url", f)
            self.assertIn("name", f)
            self.assertTrue(f["url"].startswith("http"))

    def test_known_feeds_present(self):
        ids = {f["id"] for f in datafeeds.load_catalog()["feeds"]}
        for want in ("cisa-kev", "epss", "osv", "nvd-cve"):
            self.assertIn(want, ids)

    def test_list_feeds_domain_filter(self):
        vuln = datafeeds.list_feeds(domain="vuln")
        self.assertTrue(vuln)
        for f in vuln:
            self.assertEqual(f["domain"], "vuln")

    def test_list_all(self):
        self.assertEqual(
            len(datafeeds.list_feeds()),
            len(datafeeds.load_catalog()["feeds"]),
        )


class TestCacheBehavior(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["COGNIS_FEEDS_CACHE"] = self._tmp.name

    def tearDown(self):
        os.environ.pop("COGNIS_FEEDS_CACHE", None)
        self._tmp.cleanup()

    def test_cache_dir_created(self):
        d = datafeeds.cache_dir()
        self.assertTrue(d.exists())

    def test_uncached_age_is_none(self):
        self.assertIsNone(datafeeds.cached_age_hours("never-fetched"))

    def test_offline_get_without_cache_raises(self):
        with self.assertRaises(FileNotFoundError):
            datafeeds.get("cisa-kev", offline=True)

    def test_unknown_feed_update_raises(self):
        with self.assertRaises(KeyError):
            datafeeds.update("does-not-exist")

    def test_offline_get_serves_seeded_cache(self):
        # Seed the cache by hand (simulating a prior fetch) and read offline.
        data_path, meta_path = datafeeds._paths("osv")
        data_path.write_bytes(json.dumps({"vulns": []}).encode())
        meta_path.write_text(json.dumps(
            {"feed": "osv", "fetched_at": 9e9, "bytes": 11, "format": "json"}))
        out = datafeeds.get("osv", offline=True)
        self.assertEqual(out, {"vulns": []})


class TestSnapshotRoundtrip(unittest.TestCase):
    def test_export_import(self):
        with tempfile.TemporaryDirectory() as src, \
                tempfile.TemporaryDirectory() as dst, \
                tempfile.TemporaryDirectory() as arc:
            os.environ["COGNIS_FEEDS_CACHE"] = src
            dp, mp = datafeeds._paths("kev")
            dp.write_bytes(b'{"x":1}')
            mp.write_text('{"feed":"kev","fetched_at":1,"bytes":7,"format":"json"}')
            tar = os.path.join(arc, "snap.tar.gz")
            n = datafeeds.snapshot_export(tar)
            self.assertEqual(n, 1)

            os.environ["COGNIS_FEEDS_CACHE"] = dst
            imported = datafeeds.snapshot_import(tar)
            self.assertEqual(imported, 1)
            dp2, _ = datafeeds._paths("kev")
            self.assertEqual(dp2.read_bytes(), b'{"x":1}')
        os.environ.pop("COGNIS_FEEDS_CACHE", None)


if __name__ == "__main__":
    unittest.main()
