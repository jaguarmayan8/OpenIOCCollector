#!/usr/bin/env python3
"""Tests for the shared-infrastructure domain filter.

Run:  python3 -m unittest discover -s tests -v
Needs only the standard library.
"""

import os
import sys
import unittest
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ioc_extract import (  # noqa: E402
    HOSTING,
    PLATFORM,
    InfraRules,
    extract_host,
    write_cdb,
)


def rules():
    return InfraRules(
        platform={"github.com", "githubusercontent.com", "discordapp.com",
                  "pastebin.com", "amazonaws.com"},
        hosting={"github.io", "000webhostapp.com", "netlify.app"},
    )


class TestPlatformTier(unittest.TestCase):
    def test_exact_platform_is_suppressed(self):
        reason, entry = rules().classify("github.com")
        self.assertEqual(reason, PLATFORM)
        self.assertEqual(entry, "github.com")

    def test_subdomains_of_platform_are_suppressed(self):
        # The whole point: raw.githubusercontent.com must not be blocklisted.
        for host in (
            "raw.githubusercontent.com",
            "gist.githubusercontent.com",
            "cdn.discordapp.com",
            "media.discordapp.com",
            "bucket.s3.amazonaws.com",
            "a.b.c.github.com",
        ):
            with self.subTest(host=host):
                self.assertEqual(rules().classify(host)[0], PLATFORM)

    def test_label_boundary_is_respected(self):
        # A suffix match must not degenerate into a substring match.
        for host in ("notgithub.com", "github.com.evil.tld", "evilgithub.com"):
            with self.subTest(host=host):
                self.assertIsNone(rules().classify(host)[0])

    def test_normal_domain_is_blockable(self):
        for host in ("malware-c2.example", "xn--80ak6aa92e.com", "1.2.3.4.evil.org"):
            with self.subTest(host=host):
                self.assertIsNone(rules().classify(host)[0])


class TestHostingTier(unittest.TestCase):
    def test_apex_is_suppressed(self):
        self.assertEqual(rules().classify("000webhostapp.com")[0], "hosting-apex")
        self.assertEqual(rules().classify("github.io")[0], "hosting-apex")

    def test_tenant_subdomain_stays_blockable(self):
        # Each subdomain is one customer: these are precise IOCs.
        for host in (
            "evil.000webhostapp.com",
            "evil.github.io",
            "jaguarmayan8.github.io",
            "app.netlify.app",
        ):
            with self.subTest(host=host):
                self.assertIsNone(rules().classify(host)[0])


class TestExtractHost(unittest.TestCase):
    def test_url_forms(self):
        cases = {
            "http://61.53.75.166:43450/i": "61.53.75.166",
            "https://raw.githubusercontent.com/u/r/main/x.exe": "raw.githubusercontent.com",
            "https://GitHub.com/A/B": "github.com",
            "https://example.org:8443/a?b=1": "example.org",
            "http://example.com./x": "example.com",
            "example.com/path": "example.com",
        }
        for url, want in cases.items():
            with self.subTest(url=url):
                self.assertEqual(extract_host(url), want)

    def test_garbage_rejected(self):
        for url in ("", "   ", "http://", "://nope", "-bad.com"):
            with self.subTest(url=url):
                self.assertIsNone(extract_host(url))


class TestCdbOutput(unittest.TestCase):
    def test_sorted_deduped_with_colon(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.txt")
            n = write_cdb({"b.com", "a.com", "b.com"}, path)
            self.assertEqual(n, 2)
            with open(path, encoding="utf-8") as fh:
                body = fh.read()
            self.assertEqual(body, "a.com:\nb.com:\n")

    def test_empty_input_makes_empty_file(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.txt")
            self.assertEqual(write_cdb(set(), path), 0)
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "")


class TestUrlhausParsing(unittest.TestCase):
    """The export has no header; the old parser dropped the first IOC."""

    def _csv(self, body):
        import tempfile

        fh = tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False,
                                         encoding="utf-8")
        fh.write(body)
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        return fh.name

    def test_first_data_row_is_not_dropped(self):
        from ioc_extract import read_urlhaus

        rules_obj = rules()
        import ioc_extract

        ioc_extract.RULES_HOLDER["rules"] = rules_obj
        path = self._csv(
            "# comment line\n"
            "# another\n"
            "1,2026-11-19 00:00:00,http://first-evil.com/a,online,x\n"
            "2,2026-11-19 00:00:01,http://second-evil.com/b,online,x\n"
        )
        result = read_urlhaus(path)
        self.assertEqual(result["total"], 2)
        self.assertIn("first-evil.com", result["domains"])
        self.assertFalse(result["had_header"])

    def test_real_header_is_detected_and_skipped(self):
        from ioc_extract import read_urlhaus
        import ioc_extract

        ioc_extract.RULES_HOLDER["rules"] = rules()
        path = self._csv(
            "id,dateadded,url,url_status,threat,tags\n"
            "1,2026-11-19,http://evil.com/a,online,x,y\n"
        )
        result = read_urlhaus(path)
        self.assertTrue(result["had_header"])
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["domains"], {"evil.com"})

    def test_platform_rows_are_suppressed_and_counted(self):
        from ioc_extract import read_urlhaus
        import ioc_extract

        ioc_extract.RULES_HOLDER["rules"] = rules()
        path = self._csv(
            "1,2026-11-19,http://github.com/a/raw/main/p.exe,online\n"
            "2,2026-11-19,http://raw.githubusercontent.com/b/main/q.exe,online\n"
            "3,2026-11-19,http://c2.evil.net/x,online\n"
        )
        result = read_urlhaus(path)
        self.assertEqual(result["domains"], {"c2.evil.net"})
        self.assertEqual(sum(result["suppressed"].values()), 2)
        self.assertIn("github.com", result["suppressed"])


class TestAllowlistFile(unittest.TestCase):
    def test_shipped_allowlist_parses_and_covers_known_bad_hosts(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(root, "infra_allow.txt")
        self.assertTrue(os.path.exists(path), "infra_allow.txt missing")
        r = InfraRules.load(path)
        self.assertGreater(len(r), 50)
        # Every host observed in the 2026-11-19 CDB list must be suppressed.
        for host in (
            "github.com", "raw.githubusercontent.com", "gitlab.com",
            "discord.com", "cdn.discordapp.com", "drive.google.com",
            "pastebin.com",
        ):
            with self.subTest(host=host):
                self.assertIsNotNone(r.classify(host)[0], "%s not suppressed" % host)

    def test_shipped_allowlist_keeps_tenant_subdomains(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        r = InfraRules.load(os.path.join(root, "infra_allow.txt"))
        self.assertIsNone(r.classify("evil.000webhostapp.com")[0])
        self.assertIsNone(r.classify("jaguarmayan8.github.io")[0])
        self.assertIsNone(r.classify("some-malware-c2.top")[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestThreatFox(unittest.TestCase):
    """ThreatFox carries the confidence signal URLhaus lacks."""

    def _json(self, iocs):
        import json
        import tempfile

        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                         encoding="utf-8")
        json.dump({"iocs": iocs}, fh)
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        return fh.name

    def test_domains_and_ips_split(self):
        from ioc_extract import read_threatfox

        path = self._json([
            {"ioc": "bad-c2.example", "ioc_type": "domain", "confidence_level": 100},
            {"ioc": "91.107.247.163:80", "ioc_type": "ip:port", "confidence_level": 90},
            {"ioc": "45.9.1.2", "ioc_type": "ip:port", "confidence_level": 75},
        ])
        r = read_threatfox(path)
        self.assertEqual(r["domains"], {"bad-c2.example"})
        self.assertEqual(r["ips"], {"91.107.247.163", "45.9.1.2"})

    def test_low_confidence_is_dropped(self):
        from ioc_extract import read_threatfox

        path = self._json([
            {"ioc": "sure.example", "ioc_type": "domain", "confidence_level": 100},
            {"ioc": "maybe.example", "ioc_type": "domain", "confidence_level": 50},
        ])
        r = read_threatfox(path, min_confidence=75)
        self.assertEqual(r["domains"], {"sure.example"})
        self.assertEqual(r["skipped"]["low_confidence"], 1)

    def test_hashes_are_not_domains(self):
        from ioc_extract import read_threatfox

        path = self._json([
            {"ioc": "a" * 64, "ioc_type": "sha256_hash", "confidence_level": 100},
        ])
        r = read_threatfox(path)
        self.assertEqual(r["domains"], set())
        self.assertEqual(r["ips"], set())

    def test_infra_domains_from_threatfox_are_suppressed(self):
        from ioc_extract import read_threatfox

        path = self._json([
            {"ioc": "github.com", "ioc_type": "domain", "confidence_level": 100},
            {"ioc": "payload.github.com", "ioc_type": "domain", "confidence_level": 100},
        ])
        r = read_threatfox(path, rules=rules())
        self.assertEqual(r["domains"], set())
        self.assertEqual(r["skipped"]["infra:platform"], 2)

    def test_url_ioc_is_reduced_to_host(self):
        from ioc_extract import read_threatfox

        path = self._json([
            {"ioc": "http://evil.example/a/b", "ioc_type": "url", "confidence_level": 90},
            {"ioc": "http://5.6.7.8/x", "ioc_type": "url", "confidence_level": 90},
        ])
        r = read_threatfox(path)
        self.assertEqual(r["domains"], {"evil.example"})
        self.assertEqual(r["ips"], {"5.6.7.8"})
