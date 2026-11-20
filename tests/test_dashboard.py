"""Tests for generate_dashboard.py - the feed-status and freshness logic.

The regression these lock down: every feed rendered green unless its detail
contained the literal word "Empty", so `Error - 410 Gone` was published as a
healthy feed, and a missing today-folder silently rendered as "Today's feeds".
"""
import sys
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from generate_dashboard import (  # noqa: E402
    classify_detail,
    freshness,
    latest_day_dir,
    main,
    parse_summary,
    render,
)

SUMMARY = """# Daily IOC Report - 2026-11-19 13:39

- **ssl_blacklist.csv**: 832.2 KB | ~11306 entries
- **feodo_tracker.txt**: Empty (0.6 KB) - this may be expected
- **top_malicious.txt**: 2218.0 KB | ~140106 entries
- **urlhaus.csv**: Error - 410 Gone
- **threatfox_recent.json**: 7154.8 KB | ~9486 entries
- **malwarebazaar_recent.json**: 132.4 KB | ~100 entries

**Success rate:** 4/6 feeds with data
**Approximate total IOCs collected:** 277570
"""


class TestClassify(unittest.TestCase):
    def test_error_is_not_ok(self):
        self.assertEqual(classify_detail("Error - 410 Gone"), "error")
        self.assertEqual(
            classify_detail("Error - no Auth-Key (.abusech_auth_key missing)"), "error"
        )

    def test_empty(self):
        self.assertEqual(
            classify_detail("Empty (0.6 KB) - this may be expected"), "empty"
        )
        self.assertEqual(classify_detail("Empty (query_status or no results in last 7d)"), "empty")

    def test_ok_requires_a_count(self):
        self.assertEqual(classify_detail("832.2 KB | ~11306 entries"), "ok")
        self.assertEqual(classify_detail("516.0 KB | 1200 entries"), "ok")

    def test_unrecognised_is_unknown_not_ok(self):
        self.assertEqual(classify_detail("something new"), "unknown")
        self.assertEqual(classify_detail(""), "unknown")


class TestParseSummary(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "daily_summary.md"
        self.path.write_text(SUMMARY, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_statuses(self):
        parsed = parse_summary(self.path)
        status = {f["name"]: f["status"] for f in parsed["feeds"]}
        self.assertEqual(status["urlhaus.csv"], "error")
        self.assertEqual(status["feodo_tracker.txt"], "empty")
        self.assertEqual(status["ssl_blacklist.csv"], "ok")
        self.assertEqual(len(parsed["feeds"]), 6)

    def test_meta_lines_not_treated_as_feeds(self):
        names = [f["name"] for f in parse_summary(self.path)["feeds"]]
        self.assertNotIn("Success rate", names)
        self.assertNotIn("Approximate total IOCs collected", names)

    def test_success_and_total(self):
        parsed = parse_summary(self.path)
        self.assertEqual(parsed["success"], "4/6 feeds with data")
        self.assertEqual(parsed["total"], "277570")

    def test_missing_summary(self):
        parsed = parse_summary(Path(self.tmp.name) / "nope.md")
        self.assertFalse(parsed["exists"])
        self.assertEqual(parsed["feeds"], [])


class TestLatestDay(unittest.TestCase):
    def test_old_only_folder_is_flagged_not_today(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / "Output" / "2026" / "2026-09" / "20260922"
            old.mkdir(parents=True)
            day, is_today = latest_day_dir(tmp)
            self.assertEqual(day, old)
            self.assertFalse(is_today)

    def test_today_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            today = date.today()
            d = Path(tmp) / "Output" / f"{today:%Y}" / f"{today:%Y-%m}" / f"{today:%Y%m%d}"
            d.mkdir(parents=True)
            day, is_today = latest_day_dir(tmp)
            self.assertEqual(day, d)
            self.assertTrue(is_today)

    def test_no_folders_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit):
                latest_day_dir(tmp)


class TestFreshnessAndRender(unittest.TestCase):
    def _tree(self, tmp, day_name):
        base = Path(tmp)
        day = base / "Output" / day_name[:4] / f"{day_name[:4]}-{day_name[4:6]}" / day_name
        day.mkdir(parents=True)
        (day / "daily_summary.md").write_text(SUMMARY, encoding="utf-8")
        (day / "vt_enrichment.md").write_text("# none\n", encoding="utf-8")
        for name in ("malicious-ips.txt", "malicious-domains.txt", "malicious-hashes.txt"):
            (base / name).write_text("1.2.3.4:\n", encoding="utf-8")
        return base, day

    def test_stale_when_data_is_not_from_today(self):
        with tempfile.TemporaryDirectory() as tmp:
            base, day = self._tree(tmp, "20260922")
            info = freshness(day, day / "daily_summary.md")
            self.assertTrue(info["stale"])
            self.assertFalse(info["is_today"])

    def test_render_marks_error_feed_red_and_banners_stale(self):
        with tempfile.TemporaryDirectory() as tmp:
            base, day = self._tree(tmp, "20260922")
            out = base / "docs" / "index.html"
            main(base=base, out=out)
            html = out.read_text(encoding="utf-8")
            self.assertIn('class="feed error"', html)
            self.assertIn("Error - 410 Gone", html)
            self.assertNotIn('class="feed ok"<b>urlhaus.csv', html)
            self.assertIn("STALE DATA", html)
            self.assertIn("2026-09-22", html)
            self.assertNotIn("Today's feeds", html)

    def test_fresh_day_has_no_stale_banner(self):
        with tempfile.TemporaryDirectory() as tmp:
            today = date.today()
            base, day = self._tree(tmp, f"{today:%Y%m%d}")
            (day / "daily_summary.md").write_text(
                SUMMARY.replace("2026-11-19", f"{today:%Y-%m-%d}"), encoding="utf-8"
            )
            html_out = base / "docs" / "index.html"
            main(base=base, out=html_out)
            html = html_out.read_text(encoding="utf-8")
            self.assertNotIn("STALE DATA", html)
            self.assertIn('class="feed error"', html)

    def test_old_summary_in_todays_folder_is_still_stale(self):
        with tempfile.TemporaryDirectory() as tmp:
            today = date.today()
            base, day = self._tree(tmp, f"{today:%Y%m%d}")
            summary = day / "daily_summary.md"
            summary.write_text(SUMMARY, encoding="utf-8")
            old = (datetime.now(timezone.utc) - timedelta(hours=30)).timestamp()
            import os

            os.utime(summary, (old, old))
            info = freshness(day, summary)
            self.assertTrue(info["stale"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

class TestPublishedTotals(unittest.TestCase):
    """The dashboard headline must describe the lists it publishes.

    Regression: the page showed the collector's raw feed-entry sum (277,570)
    with the word "Approximate", while the three published lists held ~144k
    deduped, confidence-filtered entries. Both numbers are real; the page now
    labels which is which.
    """

    def test_headline_reports_published_count_not_raw_sum(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            day = base / "Output" / "2026" / "2026-11" / "20261119"
            day.mkdir(parents=True)
            (day / "daily_summary.md").write_text(SUMMARY, encoding="utf-8")
            (base / "malicious-ips.txt").write_text("1.2.3.4\n5.6.7.8\n9.9.9.9\n")
            (base / "malicious-domains.txt").write_text("a.example\nb.example\n")
            (base / "malicious-hashes.txt").write_text("deadbeef\n")

            html = render(day, base=base, now=datetime(2026, 11, 19, 20, 0, tzinfo=timezone.utc))

            self.assertIn("6 unique IOCs published", html)
            self.assertIn("277,570 raw feed entries", html)
            self.assertNotIn("Approximate total IOCs collected", html)

    def test_missing_raw_total_still_renders(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            day = base / "Output" / "2026" / "2026-11" / "20261119"
            day.mkdir(parents=True)
            (day / "daily_summary.md").write_text("# Daily IOC Report - 2026-11-19 13:39\n")
            (base / "malicious-ips.txt").write_text("1.2.3.4\n")

            html = render(day, base=base, now=datetime(2026, 11, 19, 20, 0, tzinfo=timezone.utc))

            self.assertIn("1 unique IOCs published", html)
            self.assertIn("n/a raw feed entries", html)


if __name__ == "__main__":
    unittest.main()
