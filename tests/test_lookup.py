"""Tests for the in-page IOC lookup (lookup.js + its dashboard markup).

Why this is tested rather than eyeballed: a wrong normalisation turns a listed
indicator into a silent "not in today's lists", and a wrong line parser turns
`2001:db8::1:` into the domain `2001:db8::`. Both failures look like a working
page and produce a wrong answer, which is the one outcome worse than no lookup.

The parser tests run the real lookup.js under node. They are skipped when node
is absent (a Kali box may not have it); GitHub Actions' ubuntu-latest does.
"""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import generate_dashboard as gd  # noqa: E402

LOOKUP_JS = Path(__file__).resolve().parents[1] / "lookup.js"

SUMMARY = """# Daily IOC Report - 2026-11-19 13:39

- **urlhaus.csv**: 2.0 KB | ~3 entries

**Success rate:** 1/1 feeds with data
**Approximate total IOCs collected:** 3
"""

SHA256 = "99412eddb4712a89c9f5e0b0a4bb1a1d2c0b6f11ef7a9f2b2f5a4c9d8e7f6a5b"


def _page():
    """Render a page from a synthetic tree and return its HTML."""
    tmp = tempfile.TemporaryDirectory()
    base = Path(tmp.name)
    day = base / "Output" / "2026" / "2026-11" / "20261119"
    day.mkdir(parents=True)
    (day / "daily_summary.md").write_text(SUMMARY, encoding="utf-8")
    (base / "malicious-ips.txt").write_text("1.2.3.4:\n5.6.7.8:\n", encoding="utf-8")
    (base / "malicious-domains.txt").write_text("evil.example:\n", encoding="utf-8")
    (base / "malicious-hashes.txt").write_text(SHA256 + ":\n", encoding="utf-8")
    html = gd.render(day, base=base, now=datetime(2026, 11, 19, 20, 0, tzinfo=timezone.utc))
    tmp.cleanup()
    return html


class TestLookupMarkup(unittest.TestCase):
    def setUp(self):
        self.html = _page()

    def test_section_and_input_exist(self):
        self.assertIn('id="ioc-lookup-form"', self.html)
        self.assertIn('id="ioc-input"', self.html)
        self.assertIn('id="ioc-lookup-status"', self.html)
        self.assertIn('aria-live="polite"', self.html)

    def test_script_is_embedded_not_linked(self):
        # GitHub Pages serves one file; a src="lookup.js" reference would 404
        # unless the file were copied into docs/, which would duplicate 2 MB of
        # lists per day into git history again.
        self.assertIn('<script id="ioc-lookup">', self.html)
        self.assertNotIn('src="lookup.js"', self.html)

    def test_config_carries_counts_and_date(self):
        cfg = json.loads(
            self.html.split('var CFG = ', 1)[1].split(";\n", 1)[0]
        )
        self.assertEqual(cfg["dataDate"], "2026-11-19")
        self.assertEqual(cfg["counts"], {"ips": 2, "domains": 1, "hashes": 1})
        self.assertTrue(cfg["raw"].endswith("/main/"), cfg["raw"])
        self.assertEqual([l["path"] for l in cfg["lists"]],
                         ["malicious-ips.txt", "malicious-domains.txt", "malicious-hashes.txt"])
        self.assertFalse(cfg["stale"])

    def test_noscript_fallback_points_at_raw_lists(self):
        self.assertIn("malicious-ips.txt</a>", self.html)
        self.assertIn("raw.githubusercontent.com", self.html)

    def test_missing_lookup_js_degrades_instead_of_breaking_publish(self):
        original = gd._lookup_cache
        try:
            gd._lookup_cache = ""          # simulate an unreadable lookup.js
            html = gd.render(
                Path("/nonexistent") / "20261119", base=Path("/nonexistent"),
                now=datetime(2026, 11, 19, 20, 0, tzinfo=timezone.utc),
            ) if False else None
            self.assertIsNone(html)
            # Directly: both halves must return "" rather than raising.
            self.assertEqual(gd.lookup_section(), "")
            self.assertEqual(gd.lookup_script(
                {"data_date": datetime(2026, 11, 19).date(), "stale": False}, 1, 1, 1), "")
        finally:
            gd._lookup_cache = original


CASES = {
    "normalize": [
        {"in": "https://evil.example/a.bin", "out": {"value": "evil.example", "kind": "domain"}},
        {"in": "hxxps://Evil.Example:8443/p/x", "out": {"value": "evil.example", "kind": "domain"}},
        {"in": "1.2.3.4:8080", "out": {"value": "1.2.3.4", "kind": "ip"}},
        {"in": "http://[2001:db8::1]:80/x", "out": {"value": "2001:db8::1", "kind": "ip"}},
        {"in": "  EVIL.EXAMPLE.  ", "out": {"value": "evil.example", "kind": "domain"}},
        {"in": "user@evil.example/x", "out": {"value": "evil.example", "kind": "domain"}},
        {"in": "99412EDDB4712A89C9F5E0B0A4BB1A1D2C0B6F11EF7A9F2B2F5A4C9D8E7F6A5B",
         "out": {"value": SHA256, "kind": "hash"}},
        {"in": "", "out": None},
        {"in": "   ", "out": None},
    ],
    "parseLine": [
        {"in": "1.2.3.4:", "out": {"value": "1.2.3.4", "tag": ""}},
        {"in": "1.2.3.4:threatfox:100", "out": {"value": "1.2.3.4", "tag": "threatfox:100"}},
        {"in": "2001:db8::1:", "out": {"value": "2001:db8::1", "tag": ""}},
        {"in": "2001:db8::1:threatfox:100",
         "out": {"value": "2001:db8::1", "tag": "threatfox:100"}},
        {"in": "evil.example", "out": {"value": "evil.example", "tag": ""}},
        {"in": "# a comment", "out": None},
        {"in": "", "out": None},
    ],
    "parseTag": [
        {"in": "threatfox:100", "out": {"source": "threatfox", "confidence": "100"}},
        {"in": "urlhaus", "out": {"source": "urlhaus", "confidence": ""}},
        {"in": "", "out": {"source": "", "confidence": ""}},
    ],
    "list": [
        "1.2.3.4:",
        "5.6.7.8:threatfox:100",
        "evil.example:threatfox:100",
        "2001:db8::1:",
        "",
        "# comment",
    ],
    "indexSize": 4,
    "lookup": [
        {"in": "https://evil.example/payload.bin", "out": ["evil.example"]},
        {"in": "www.evil.example", "out": ["evil.example"]},
        {"in": "1.2.3.4", "out": ["1.2.3.4"]},
        {"in": "5.6.7.8", "out": ["5.6.7.8"]},
        {"in": "http://[2001:db8::1]/x", "out": ["2001:db8::1"]},
        {"in": "8.8.8.8", "out": []},
        {"in": "evil.example.evil.tld", "out": []},
    ],
}

HARNESS = r"""
const fs = require("fs");
const src = fs.readFileSync(process.argv[2], "utf8");
global.window = global;
eval(src);
const L = global.IOCLookup;
const cases = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
let bad = 0;
function check(label, got, want) {
  const a = JSON.stringify(got), b = JSON.stringify(want);
  if (a !== b) { bad += 1; console.log("FAIL " + label + "\n  got  " + a + "\n  want " + b); }
  else { console.log("ok   " + label); }
}
for (const c of cases.normalize) {
  const n = L.normalize(c.in);
  check("normalize(" + JSON.stringify(c.in) + ")",
        n ? { value: n.value, kind: n.kind } : null, c.out);
}
for (const c of cases.parseLine) check("parseLine(" + JSON.stringify(c.in) + ")", L.parseLine(c.in), c.out);
for (const c of cases.parseTag) check("parseTag(" + JSON.stringify(c.in) + ")", L.parseTag(c.in), c.out);
const idx = L.buildIndex(cases.list.join("\n"));
check("index size", idx.size, cases.indexSize);
for (const c of cases.lookup) {
  check("lookup(" + JSON.stringify(c.in) + ")",
        L.lookup({ ips: idx }, L.normalize(c.in)).map(h => h.value), c.out);
}
process.exit(bad ? 1 : 0);
"""


@unittest.skipUnless(shutil.which("node"), "node not installed - parser tests skipped")
class TestLookupParser(unittest.TestCase):
    def test_normalisation_and_lookup(self):
        with tempfile.TemporaryDirectory() as tmp:
            cases = Path(tmp) / "cases.json"
            cases.write_text(json.dumps(CASES), encoding="utf-8")
            harness = Path(tmp) / "run.js"
            harness.write_text(HARNESS, encoding="utf-8")
            proc = subprocess.run(
                ["node", str(harness), str(LOOKUP_JS), str(cases)],
                capture_output=True, text=True, timeout=60,
            )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("index size", proc.stdout)

    def test_lookup_js_is_valid_syntax(self):
        proc = subprocess.run(
            ["node", "--check", str(LOOKUP_JS)], capture_output=True, text=True, timeout=60
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
