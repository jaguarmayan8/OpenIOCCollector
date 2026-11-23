"""Regression tests for the ThreatFox -> CDB list wiring.

ThreatFox was collected daily and used only for hashes; its domains, C2
ip:port entries and URL hosts never reached the published lists, while the
dashboard kept counting the feed as healthy. These tests drive the exact
function build_lists.sh calls (`ioc_extract.py lists`) over a payload shaped
like the live get_iocs response, so the "only URLhaus is parsed" regression
fails the suite instead of silently shipping.
"""
import argparse
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ioc_extract  # noqa: E402

URLHAUS_NO_HEADER = "\n".join(
    [
        "# urlhaus export (no header row)",
        "3700001,2026-11-19 10:00:00,http://urlhaus-evil.test/payload.bin",
        "3700002,2026-11-19 10:01:00,https://cdn.github.com/benign-ish",
    ]
) + "\n"

THREATFOX = {
    "query_status": "ok",
    "iocs": [
        # high-confidence domain, unique to ThreatFox
        {"ioc": "tf-c2-evil.test", "ioc_type": "domain", "confidence_level": 100},
        # low-confidence domain - the deliberate >=75 cut must drop it
        {"ioc": "tf-lowconf.test", "ioc_type": "domain", "confidence_level": 50},
        # C2 ip:port - port must be stripped for a CDB IP entry
        {"ioc": "203.0.113.9:8080", "ioc_type": "ip:port", "confidence_level": 90},
        # URL whose host is a domain not otherwise listed
        {"ioc": "http://tf-url-host.test/gate.php", "ioc_type": "url", "confidence_level": 80},
        # platform domain - must stay out of the list
        {"ioc": "github.com", "ioc_type": "domain", "confidence_level": 100},
        # hashes are handled by build_lists.sh, not the list builder
        {"ioc": "d41d8cd98f00b204e9800998ecf8427e", "ioc_type": "md5_hash", "confidence_level": 100},
    ],
}

ALLOW = """\
# tier   domain
platform github.com
platform raw.githubusercontent.com
hosting  trycloudflare.com
"""


class TestThreatFoxWiring(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.urlhaus = self.dir / "urlhaus.csv"
        self.urlhaus.write_text(URLHAUS_NO_HEADER, encoding="utf-8")
        self.tf = self.dir / "threatfox_recent.json"
        self.tf.write_text(json.dumps(THREATFOX), encoding="utf-8")
        self.allow = self.dir / "infra_allow.txt"
        self.allow.write_text(ALLOW, encoding="utf-8")
        self.domains = self.dir / "malicious-domains.txt"
        self.ips = self.dir / "malicious-ips.txt"

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self):
        args = argparse.Namespace(
            urlhaus=str(self.urlhaus),
            threatfox=str(self.tf),
            allow=str(self.allow),
            domains_out=str(self.domains),
            ips_out=str(self.ips),
            min_confidence=75,
            report=None,
        )
        ioc_extract.cmd_lists(args)

    def _values(self, path):
        """Keys only: `1.2.3.4:threatfox:100` -> `1.2.3.4`."""
        keys = set()
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if line:
                keys.add(ioc_extract.parse_tagged(line)[0])
        return keys

    def test_threatfox_domain_reaches_the_domain_list(self):
        self._run()
        domain_values = self._values(self.domains)
        self.assertIn("tf-c2-evil.test", domain_values)
        self.assertIn("urlhaus-evil.test", domain_values)
        self.assertIn("tf-url-host.test", domain_values)

    def test_low_confidence_and_platform_domains_are_excluded(self):
        self._run()
        domain_values = self._values(self.domains)
        self.assertNotIn("tf-lowconf.test", domain_values)
        self.assertNotIn("github.com", domain_values)
        self.assertNotIn("cdn.github.com", domain_values)

    def test_ip_port_is_published_as_bare_ip(self):
        self._run()
        ip_values = self._values(self.ips)
        self.assertIn("203.0.113.9", ip_values)
        self.assertNotIn("203.0.113.9:8080", ip_values)

    def test_cdb_format_is_key_then_provenance(self):
        """`key:source:confidence` - one line per key, provenance always present."""
        self._run()
        for path in (self.domains, self.ips):
            lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l]
            keys = [l.split(":", 1)[0] for l in lines]
            self.assertEqual(len(keys), len(set(keys)), "duplicate CDB key in %s" % path)
            for line in lines:
                key, _, tag = line.partition(":")
                self.assertNotIn(":", key, line)
                self.assertRegex(tag, r"^[a-z]+(:\d+)?(\|[a-z]+(:\d+)?)*$", line)

    def test_provenance_carries_the_feed_confidence(self):
        self._run()
        dom = self.domains.read_text(encoding="utf-8").splitlines()
        self.assertIn("tf-c2-evil.test:threatfox:100", dom)
        self.assertIn("urlhaus-evil.test:urlhaus", dom)
        ip = self.ips.read_text(encoding="utf-8").splitlines()
        self.assertIn("203.0.113.9:threatfox:90", ip)

    def test_urlhaus_header_row_is_not_dropped(self):
        # The export has no header; a parser that skips row 1 loses an IOC/day.
        self._run()
        self.assertIn("urlhaus-evil.test", self._values(self.domains))


if __name__ == "__main__":
    unittest.main(verbosity=2)
