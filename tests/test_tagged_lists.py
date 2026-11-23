"""Tests for provenance-tagged CDB values (`key:source:confidence`).

The value is what makes a published list explain itself. The failure mode this
locks down is subtle: appending tags without merging would put TWO lines with
the same key into the CDB file (`1.2.3.4:` from IPsum and
`1.2.3.4:threatfox:100` from ThreatFox), and a duplicate key is a different
database entry, not a richer one.
"""
import argparse
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ioc_extract  # noqa: E402


class TestProvenance(unittest.TestCase):
    def test_single_source_with_confidence(self):
        p = ioc_extract.Provenance()
        p.add("1.2.3.4", "threatfox", 100)
        self.assertEqual(p.lines(), ["1.2.3.4:threatfox:100"])

    def test_source_without_confidence_has_no_number(self):
        p = ioc_extract.Provenance()
        p.add("5.6.7.8", "ipsum")
        self.assertEqual(p.lines(), ["5.6.7.8:ipsum"])

    def test_same_key_from_two_feeds_is_one_line(self):
        p = ioc_extract.Provenance()
        p.add("1.2.3.4", "ipsum")
        p.add("1.2.3.4", "threatfox", 100)
        lines = p.lines()
        self.assertEqual(len(lines), 1, lines)
        self.assertEqual(lines[0], "1.2.3.4:threatfox:100|ipsum")

    def test_confidence_order_is_stable(self):
        p = ioc_extract.Provenance()
        p.add("1.2.3.4", "urlhaus")
        p.add("1.2.3.4", "threatfox", 75)
        p.add("1.2.3.4", "feodo", 90)
        self.assertEqual(p.lines(), ["1.2.3.4:feodo:90|threatfox:75|urlhaus"])

    def test_highest_confidence_wins_for_one_feed(self):
        p = ioc_extract.Provenance()
        p.add("1.2.3.4", "threatfox", 50)
        p.add("1.2.3.4", "threatfox", 100)
        self.assertEqual(p.lines(), ["1.2.3.4:threatfox:100"])


class TestParseTagged(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(ioc_extract.parse_tagged("1.2.3.4:"), ("1.2.3.4", ""))
        self.assertEqual(ioc_extract.parse_tagged("1.2.3.4:threatfox:100"),
                         ("1.2.3.4", "threatfox:100"))
        self.assertEqual(ioc_extract.parse_tagged("1.2.3.4"), ("1.2.3.4", ""))
        self.assertEqual(ioc_extract.parse_tagged("# c"), (None, None))
        self.assertEqual(ioc_extract.parse_tagged(""), (None, None))

    def test_round_trip(self):
        p = ioc_extract.Provenance()
        p.add("evil.example", "threatfox", 100)
        p.add("evil.example", "urlhaus")
        line = p.lines()[0]
        self.assertEqual(ioc_extract.parse_tagged(line), ("evil.example", "threatfox:100|urlhaus"))


class TestCommands(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_merge_unions_by_key_not_by_line(self):
        a = self.d / "a.txt"
        b = self.d / "b.txt"
        a.write_text("1.2.3.4:\n9.9.9.9:\n", encoding="utf-8")
        b.write_text("1.2.3.4:threatfox:100\n", encoding="utf-8")
        out = self.d / "out.txt"
        ioc_extract.cmd_merge(argparse.Namespace(out=str(out), inputs=[str(a), str(b)]))
        lines = out.read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines, ["1.2.3.4:threatfox:100", "9.9.9.9:"])

    def test_ips_builds_ipsum_plus_threatfox(self):
        ipsum = self.d / "top_malicious.txt"
        ipsum.write_text("# comment\n1.2.3.4\n5.6.7.8 # trailing\n", encoding="utf-8")
        tf = self.d / "tf.json"
        tf.write_text(json.dumps({"iocs": [
            {"ioc": "5.6.7.8:443", "ioc_type": "ip:port", "confidence_level": 90},
            {"ioc": "9.9.9.9", "ioc_type": "ip", "confidence_level": 50},
        ]}), encoding="utf-8")
        out = self.d / "ips.txt"
        ioc_extract.cmd_ips(argparse.Namespace(
            ipsum=str(ipsum), threatfox=str(tf), allow=None,
            out=str(out), min_confidence=75))
        lines = out.read_text(encoding="utf-8").splitlines()
        self.assertIn("1.2.3.4:ipsum", lines)
        self.assertIn("5.6.7.8:threatfox:90|ipsum", lines)
        self.assertNotIn("9.9.9.9:threatfox:50", lines)   # below the cut
        keys = [l.split(":", 1)[0] for l in lines]
        self.assertEqual(len(keys), len(set(keys)))

    def test_hashes_carry_confidence(self):
        tf = self.d / "tf.json"
        tf.write_text(json.dumps({"iocs": [
            {"ioc": "d41d8cd98f00b204e9800998ecf8427e", "ioc_type": "md5_hash",
             "confidence_level": 100},
        ]}), encoding="utf-8")
        out = self.d / "h.txt"
        ioc_extract.cmd_hashes(argparse.Namespace(threatfox=str(tf), out=str(out)))
        self.assertEqual(out.read_text(encoding="utf-8").strip(),
                         "d41d8cd98f00b204e9800998ecf8427e:threatfox:100")

    def test_published_keys_are_ipv4_only(self):
        """Wazuh needs `:`-containing keys quoted, so an IPv6 key would break
        the format silently. The feeds emit IPv4 only today; fail loudly if
        that ever changes."""
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "x.txt"
            ioc_extract.Provenance().add("1.2.3.4", "ipsum")
            self.assertTrue(all(":" not in l.split(":", 1)[0] for l in ["1.2.3.4:ipsum"]))
            f.write_text("1.2.3.4:ipsum\n", encoding="utf-8")
            for line in f.read_text(encoding="utf-8").splitlines():
                self.assertNotIn(":", ioc_extract.parse_tagged(line)[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
