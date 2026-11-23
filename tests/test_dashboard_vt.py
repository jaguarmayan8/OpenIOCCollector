"""Tests for the VirusTotal summary and the expected-empty feed config.

Two regressions locked down here:

  * The VT table cut hashes to 16 characters and rendered
    `Found: False / Malicious: 0` for hashes VirusTotal had never seen - which
    reads as a clean verdict on a sample nothing had analysed. Unknown is not
    clean, and the two must never be added together.
  * Feodo Tracker has shipped an empty dataset since Operation Endgame, so its
    daily amber "empty" row was a permanent false alarm. A warning colour that
    never clears is how an operator learns to ignore the one that matters.
"""
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import generate_dashboard as gd  # noqa: E402

H1 = "99412eddb4712a891754cbab961766a231154b4e47e92545891b95fc46101d9f"
H2 = "7a656791b445fff0a1f904c29d708e923624c7b2fdc001f8ea184e17f70d020a"
H3 = "90429399cf489e75b6c84b5ce8f255aa1ede10bb49112440c8d76e3185e02a22"


def rows_mixed():
    return [
        {"hash": H1, "found": True, "malicious": 19, "suspicious": 0,
         "label": "trojan.mirai/svirtu", "threatfox_malware": "Mirai"},
        {"hash": H2, "found": True, "malicious": 34, "suspicious": 0,
         "label": "trojan.adbminer/berbew", "threatfox_malware": "Hajime"},
        {"hash": H3, "found": False, "malicious": 0, "suspicious": 0,
         "label": "", "threatfox_malware": "Unknown malware"},
        {"hash": "a" * 64, "found": "False", "malicious": 0, "suspicious": 0,
         "label": "", "threatfox_malware": ""},
    ]


class TestVtSummary(unittest.TestCase):
    def test_unknown_is_not_clean(self):
        s = gd.vt_summary(rows_mixed())
        self.assertEqual(s["checked"], 4)
        self.assertEqual(s["hits"], 2)
        self.assertEqual(s["unknown"], 2)
        self.assertEqual(s["clean"], 0)
        # the three headline numbers must not double-count the unknown rows
        self.assertEqual(s["hits"] + s["clean"] + s["unknown"], s["checked"])

    def test_known_clean_counts_separately(self):
        rows = rows_mixed() + [
            {"hash": "b" * 64, "found": True, "malicious": 0, "suspicious": 0}
        ]
        s = gd.vt_summary(rows)
        self.assertEqual(s["clean"], 1)
        self.assertEqual(s["found"], 3)

    def test_errors_are_not_counted_as_unknown(self):
        rows = rows_mixed() + [{"hash": "c" * 64, "error": "429 rate limited"}]
        s = gd.vt_summary(rows)
        self.assertEqual(s["errors"], 1)
        self.assertEqual(s["unknown"], 2)
        self.assertEqual(s["checked"], 5)

    def test_found_as_string_is_understood(self):
        s = gd.vt_summary([{"hash": "d" * 64, "found": "True", "malicious": 3}])
        self.assertEqual(s["hits"], 1)
        self.assertEqual(s["unknown"], 0)


class TestVtSection(unittest.TestCase):
    def _html(self, rows):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        day = base / "Output" / "2026" / "2026-11" / "20261121"
        day.mkdir(parents=True)
        (day / "daily_summary.md").write_text(
            "# Daily IOC Report - 2026-11-21 12:52\n\n"
            "- **urlhaus.csv**: 2.0 KB | ~3 entries\n\n"
            "**Success rate:** 1/1 feeds with data\n"
            "**Approximate total IOCs collected:** 3\n",
            encoding="utf-8",
        )
        (day / "vt_enrichment.json").write_text(json.dumps(rows), encoding="utf-8")
        for name in ("malicious-ips.txt", "malicious-domains.txt", "malicious-hashes.txt"):
            (base / name).write_text("1.2.3.4:\n", encoding="utf-8")
        return gd.render(day, base=base,
                         now=datetime(2026, 11, 21, 20, 0, tzinfo=timezone.utc))

    def test_full_hash_is_present_and_linked(self):
        html = self._html(rows_mixed())
        self.assertIn(H1, html)                      # untruncated
        self.assertNotIn(H1[:16] + "…", html)        # the old truncated form is gone
        self.assertIn("https://www.virustotal.com/gui/file/" + H1, html)

    def test_says_it_is_a_sample_not_a_verdict(self):
        html = self._html(rows_mixed())
        self.assertIn("not a verdict on the", html)
        self.assertIn("unknown to VirusTotal", html)
        self.assertIn("not</b> counted as clean", html)

    def test_no_old_table_headers(self):
        html = self._html(rows_mixed())
        self.assertNotIn("<th>Suspicious</th>", html)
        self.assertNotIn("Found</th>", html)

    def test_empty_sample_still_renders(self):
        html = self._html([])
        self.assertIn("No VirusTotal sample for this day.", html)


class TestExpectedEmpty(unittest.TestCase):
    SUMMARY = (
        "# Daily IOC Report - 2026-11-21 12:52\n\n"
        "- **feodo_tracker.txt**: Empty (0.6 KB) - this may be expected\n"
        "- **urlhaus.csv**: 2.0 KB | ~3 entries\n\n"
        "**Success rate:** 1/2 feeds with data\n"
        "**Approximate total IOCs collected:** 3\n"
    )

    def _render(self, feodo_line=None, day_name="20261121"):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        day = base / "Output" / "2026" / "2026-11" / day_name
        day.mkdir(parents=True)
        summary = self.SUMMARY
        if feodo_line is not None:
            summary = summary.replace(
                "- **feodo_tracker.txt**: Empty (0.6 KB) - this may be expected",
                feodo_line,
            )
        (day / "daily_summary.md").write_text(summary, encoding="utf-8")
        for name in ("malicious-ips.txt", "malicious-domains.txt", "malicious-hashes.txt"):
            (base / name).write_text("1.2.3.4:\n", encoding="utf-8")
        return gd.render(day, base=base,
                         now=datetime(2026, 11, 21, 20, 0, tzinfo=timezone.utc))

    def test_configured_empty_feed_is_not_a_warning(self):
        feeds = gd.apply_feed_config(
            [{"name": "feodo_tracker.txt", "detail": "Empty (0.6 KB)", "status": "empty"}]
        )
        self.assertEqual(feeds[0]["status"], "expected")
        self.assertTrue(feeds[0]["note"])

    def test_expected_feed_does_not_turn_the_card_amber(self):
        html = self._render()
        self.assertIn('class="feed expected"', html)
        self.assertIn("expected empty", html)
        self.assertNotIn('class="card warn"', html)
        self.assertNotIn("1 empty/unknown", html)

    def test_unconfigured_empty_feed_still_warns(self):
        feeds = gd.apply_feed_config(
            [{"name": "some_new_feed.csv", "detail": "Empty (0.1 KB)", "status": "empty"}]
        )
        self.assertEqual(feeds[0]["status"], "empty")

    def test_error_on_a_configured_feed_stays_red(self):
        feeds = gd.apply_feed_config(
            [{"name": "feodo_tracker.txt", "detail": "Error - 410 Gone", "status": "error"}]
        )
        self.assertEqual(feeds[0]["status"], "error")
        html = self._render(feodo_line="- **feodo_tracker.txt**: Error - 410 Gone")
        self.assertIn('class="feed error"', html)
        self.assertIn('class="card bad"', html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
