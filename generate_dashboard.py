#!/usr/bin/env python3
"""Render docs/index.html from the newest daily output folder.

Trust rules (why this file is shaped the way it is):

  * A feed's colour comes from what the collector WROTE, not from a substring
    guess. "Error - 410 Gone" used to render green because anything that was
    not the word "Empty" was treated as healthy. Statuses are now explicit:
    ok / empty / unknown / error, and only `ok` is green.
  * The page never claims "today" on its own authority. It reads the date from
    the folder name it actually rendered, compares it to the local date, and
    shows a STALE banner when they differ - so a dead cron cannot keep serving
    week-old IOCs under a "Today's feeds" heading.
  * Timestamps are shown with an explicit timezone and an age, because a bare
    "last run 13:39" cannot be distinguished from three days ago.
  * The page can answer "is this indicator in today's lists?" with no backend:
    lookup.js fetches the three CDB lists from the repo's raw URLs on first use
    and indexes them in the browser. Counts alone make the page a poster; the
    lookup is what a SOC analyst can actually use mid-investigation.
"""
from __future__ import annotations

from datetime import date, datetime
from pathlib import Path
import hashlib
import json
import re
import subprocess
import sys

BASE = Path(__file__).resolve().parent
OUT_HTML = BASE / "docs" / "index.html"
REPO = "https://github.com/jaguarmayan8/OpenIOCCollector"
# Raw base for the lists the in-page lookup fetches. Verified against the live
# files: raw.githubusercontent.com answers `access-control-allow-origin: *`, so
# the dashboard reads the CDN copy directly and needs no backend of its own.
# The lists are NOT copied into docs/ - that would put ~2.2 MB of daily-changing
# text into git history again, which is the 1 GB problem SIZE_FIX.md documents.
REPO_RAW = "https://raw.githubusercontent.com/jaguarmayan8/OpenIOCCollector/main"

PAGES_URL = "https://jaguarmayan8.github.io/OpenIOCCollector"
LOOKUP_JS_PATH = BASE / "lookup.js"
CONFIG_SENTINEL = "/*__CONFIG__*/ {}"   # replaced by the JSON config object
_lookup_cache = None


def _lookup_js_text():
    """lookup.js, or "" when this checkout is missing it.

    A missing lookup.js must not take the publish down: the CDB lists and the
    dashboard are the product, the lookup is a feature on top of them. It warns
    loudly and the page renders without the box.
    """
    global _lookup_cache
    if _lookup_cache is None:
        try:
            _lookup_cache = LOOKUP_JS_PATH.read_text(encoding="utf-8")
        except OSError as exc:
            print(
                "[!] lookup.js unreadable (%s) - publishing the dashboard without "
                "the lookup box" % exc,
                file=sys.stderr,
            )
            _lookup_cache = ""
    return _lookup_cache


def lookup_section():
    """The lookup card, or "" if the script is unavailable."""
    if not _lookup_js_text():
        return ""
    return f"""  <section class="card" style="margin-top:16px;" id="lookup">
    <h2>Look up an indicator</h2>
    <p class="hint">Checks today's published lists in your browser — nothing is uploaded.
       Accepts an IP, a domain, a full URL (scheme, port, path and <code>www.</code> are
       ignored) or a 32/40/64-character hash.</p>
    <form class="lookup" id="ioc-lookup-form" autocomplete="off" role="search">
      <label class="sr-only" for="ioc-input">IP, domain, URL or file hash</label>
      <input id="ioc-input" type="search" spellcheck="false" autocapitalize="none"
             placeholder="evil.example · 1.2.3.4 · hxxps://evil.example/a.bin · d41d8cd9…">
      <button type="submit">Check</button>
    </form>
    <p class="status" id="ioc-lookup-status" role="status" aria-live="polite">Lists load on first use.</p>
    <div class="result" id="ioc-lookup-result" role="region" aria-label="Lookup result" hidden></div>
    <noscript>
      <p class="hint">JavaScript is off, so the in-page lookup is unavailable. Download
        <a href="{REPO_RAW}/malicious-ips.txt">malicious-ips.txt</a>,
        <a href="{REPO_RAW}/malicious-domains.txt">malicious-domains.txt</a> or
        <a href="{REPO_RAW}/malicious-hashes.txt">malicious-hashes.txt</a> and grep them.</p>
    </noscript>
  </section>

"""


def lookup_script(info, ips, domains, hashes):
    """The inlined script tag with its config, or "" if unavailable."""
    js = _lookup_js_text()
    if not js:
        return ""
    cfg = {
        "raw": REPO_RAW + "/",
        "dataDate": f"{info['data_date']:%Y-%m-%d}",
        "stale": bool(info["stale"]),
        "lists": [
            {"key": "ips", "label": "IP list", "path": "malicious-ips.txt"},
            {"key": "domains", "label": "Domain list", "path": "malicious-domains.txt"},
            {"key": "hashes", "label": "Hash list", "path": "malicious-hashes.txt"},
        ],
        "counts": {"ips": ips, "domains": domains, "hashes": hashes},
    }
    body = js.replace(CONFIG_SENTINEL, json.dumps(cfg, sort_keys=True), 1)
    return '<script id="ioc-lookup">\n%s\n</script>' % body

# A day is "stale" once the summary is older than this, even if the folder
# still carries today's date (e.g. the cron ran at 04:30 and died mid-run).
STALE_AFTER_HOURS = 26

STATUSES = ("ok", "empty", "expected", "unknown", "error")

# A feed that is empty because that is its normal state, not because something
# broke. abuse.ch states Feodo Tracker has shipped an empty dataset since
# Operation Endgame, so flagging it amber every single day is a warning that is
# permanently wrong - and a colour that never clears is how people learn to
# ignore the one that does.
FEED_CONFIG = {
    "feodo_tracker.txt": {
        "expected_empty": True,
        "note": "abuse.ch: no active C2 servers since Operation Endgame",
    },
}

# VirusTotal "malicious" votes at or above this count as a detection.
VT_HIT_MIN = 1
VT_GUI = "https://www.virustotal.com/gui/file/"

# Only set by the offline preview builder; never true in the pipeline.
DEBUG_NO_LINKS = False


def apply_feed_config(feeds):
    """Tag expected-empty feeds. An ERROR is never downgraded.

    "The feed answered and had nothing" and "the feed never answered" stay
    different things: a 410 from Feodo is still a red row.
    """
    for feed in feeds:
        cfg = FEED_CONFIG.get(feed.get("name"))
        if not cfg:
            continue
        feed["expected_empty"] = bool(cfg.get("expected_empty"))
        feed["note"] = cfg.get("note", "")
        if feed["status"] == "empty" and feed["expected_empty"]:
            feed["status"] = "expected"
    return feeds


def _vt_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _vt_found(row):
    value = row.get("found")
    return value is True or str(value).strip().lower() == "true"


def vt_summary(rows):
    """Counts behind the VirusTotal headline.

    "Not found" is not "clean". VirusTotal answers 404 for a hash it has never
    seen, and the previous table rendered that as `Found: False` next to
    `Malicious: 0` - which reads as a clean verdict on a sample nothing had
    analysed. Unknown and clean are counted separately and never added.
    """
    errors = [r for r in rows if "error" in r]
    ok = [r for r in rows if "error" not in r]
    found = [r for r in ok if _vt_found(r)]
    hits = [r for r in ok if _vt_int(r.get("malicious")) >= VT_HIT_MIN]
    clean = [
        r
        for r in found
        if _vt_int(r.get("malicious")) == 0 and _vt_int(r.get("suspicious")) == 0
    ]
    unknown = [r for r in ok if not _vt_found(r)]
    return {
        "checked": len(rows),
        "errors": len(errors),
        "found": len(found),
        "hits": len(hits),
        "clean": len(clean),
        "unknown": len(unknown),
    }


def classify_detail(detail):
    """Map a collector summary detail string to an explicit status.

    The collector writes exactly four shapes (collector.py `record()`):
        "832.2 KB | ~11306 entries"   -> ok
        "Empty (0.6 KB) - ..."        -> empty
        "Error - 410 Gone"            -> error
        "Error - no Auth-Key (...)"   -> error
    Anything unrecognised is `unknown` (amber), never green.
    """
    text = (detail or "").strip()
    if re.match(r"(?i)^error\b", text):
        return "error"
    if re.match(r"(?i)^empty\b", text):
        return "empty"
    if re.search(r"\|\s*~?\d+\s+entr", text):
        return "ok"
    return "unknown"


def latest_day_dir(base=None):
    """Newest Output/*/*/YYYYMMDD folder plus whether it is today's.

    Returns (path, is_today). Falls back to the newest existing folder - but
    callers must present that fallback as stale, never as today's data.
    """
    base = Path(base) if base else BASE
    today = date.today()
    today_dir = base / "Output" / f"{today:%Y}" / f"{today:%Y-%m}" / f"{today:%Y%m%d}"
    if today_dir.is_dir():
        return today_dir, True
    days = sorted(base.glob("Output/*/*/[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]"))
    if not days:
        raise SystemExit("No daily output folders found")
    return days[-1], False


def count_lines(path):
    path = Path(path)
    if not path.exists():
        return 0
    return sum(
        1
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip()
    )


def fmt_num(value):
    """'278791' -> '278,791'; anything non-numeric ("n/a") passes through."""
    text = str(value).strip()
    return f"{int(text):,}" if text.isdigit() else text


def parse_summary(path):
    """Parse daily_summary.md into a dict of feeds, success rate and total."""
    path = Path(path)
    out = {
        "run_label": "unknown",
        "run_dt": None,
        "feeds": [],
        "success": "n/a",
        "total": "n/a",
        "exists": path.exists(),
    }
    if not path.exists():
        return out

    text = path.read_text(encoding="utf-8", errors="ignore")
    m = re.search(r"Daily IOC Report\s*-\s*(.+)", text)
    if m:
        out["run_label"] = m.group(1).strip()
        try:
            out["run_dt"] = datetime.strptime(out["run_label"], "%Y-%m-%d %H:%M")
        except ValueError:
            out["run_dt"] = None

    for line in text.splitlines():
        m = re.search(r"\*\*(.+?)\*\*:\s*(.+)", line)
        if not m:
            continue
        name, detail = m.group(1), m.group(2)
        if "Success rate" in name or "Approximate" in name:
            continue
        out["feeds"].append(
            {"name": name, "detail": detail, "status": classify_detail(detail)}
        )

    m = re.search(r"Success rate:\*\*\s*(.+)", text)
    if m:
        out["success"] = m.group(1).strip()
    m = re.search(r"Approximate total IOCs collected:\*\*\s*(.+)", text)
    if m:
        out["total"] = m.group(1).strip()
    return out


def vt_rows(json_path, md_path):
    rows = []
    json_path, md_path = Path(json_path), Path(md_path)
    if json_path.exists():
        data = json.loads(json_path.read_text(encoding="utf-8"))
        for item in data:
            rows.append(
                {
                    "hash": item.get("hash", ""),
                    "found": str(item.get("found", "")),
                    "malicious": item.get("malicious", ""),
                    "suspicious": item.get("suspicious", ""),
                    "label": item.get("label", "") or "",
                    "malware": item.get("threatfox_malware", "") or "",
                }
            )
        return rows
    if md_path.exists():
        for line in md_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("| `"):
                parts = [p.strip().strip("`") for p in line.strip("|").split("|")]
                if len(parts) >= 6:
                    rows.append(
                        {
                            "hash": parts[0],
                            "found": parts[1],
                            "malicious": parts[2],
                            "suspicious": parts[3],
                            "label": parts[4],
                            "malware": parts[5],
                        }
                    )
    return rows


def esc(s):
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def freshness(day, summary_path, now=None):
    """Human-readable data age + whether the page must carry a STALE banner."""
    now = now or datetime.now().astimezone()
    data_date = datetime.strptime(Path(day).name, "%Y%m%d").date()
    summary_path = Path(summary_path)
    if summary_path.exists():
        generated = datetime.fromtimestamp(summary_path.stat().st_mtime).astimezone()
    else:
        generated = None
    age_hours = ((now - generated).total_seconds() / 3600.0) if generated else None

    is_today = data_date == now.date()
    stale = (not is_today) or age_hours is None or age_hours > STALE_AFTER_HOURS
    return {
        "data_date": data_date,
        "generated": generated,
        "age_hours": age_hours,
        "is_today": is_today,
        "stale": stale,
    }


def _age_text(hours):
    if hours is None:
        return "unknown age"
    if hours < 1:
        return f"{int(hours * 60)} min ago"
    if hours < 48:
        return f"{hours:.1f} h ago"
    return f"{hours / 24:.1f} days ago"


def render_vt_section(rows, day):
    """Three numbers plus the full hashes, never a wall of truncated rows.

    The old table showed 20 rows cut to 16 characters each, a third of them
    `Found: False / Unknown malware` - which is noise, not evidence: those rows
    were hashes VirusTotal had never seen. The numbers answer "is this feed
    worth sampling?" and the hash list stays available, in full and linked,
    for the one analyst who wants to look one up.
    """
    stats = vt_summary(rows)
    day_name = Path(day).name
    raw_href = "%s/blob/main/Output/%s/%s-%s/%s/vt_enrichment.json" % (
        REPO, day_name[:4], day_name[:4], day_name[4:6], day_name
    )

    if not rows:
        return (
            '  <section class="card" style="margin-top:16px;">'
            "<h2>VirusTotal sample</h2>"
            '<p class="sub">No VirusTotal sample for this day.</p></section>\n'
        )

    cards = "".join(
        '<div class="card%s"><div class="num">%s</div>'
        '<div class="label">%s</div></div>' % (cls, n, label)
        for cls, n, label in (
            ("", fmt_num(stats["checked"]), "hashes checked"),
            (" bad" if stats["hits"] else "", fmt_num(stats["hits"]),
             "with ≥1 VT detection"),
            ("", fmt_num(stats["clean"]), "VT-clean"),
        )
    )

    caveats = [
        "A sample of %s hashes from ThreatFox — not a verdict on the hash list "
        "or on the corpus." % fmt_num(stats["checked"])
    ]
    if stats["unknown"]:
        caveats.append(
            "%s of them are unknown to VirusTotal (never submitted or not yet "
            "analysed) and are <b>not</b> counted as clean."
            % fmt_num(stats["unknown"])
        )
    if stats["errors"]:
        caveats.append("%s lookup(s) failed." % fmt_num(stats["errors"]))
    caveat_html = " ".join('<span>%s</span>' % c for c in caveats)

    def rank(row):
        return (
            -_vt_int(row.get("malicious")),
            -_vt_int(row.get("suspicious")),
            row.get("hash", ""),
        )

    items = []
    for row in sorted(rows, key=rank):
        h = esc(row.get("hash", ""))
        parts = []
        if "error" in row:
            verdict = "lookup failed: %s" % esc(row["error"])
        elif not _vt_found(row):
            verdict = "not seen by VirusTotal"
        else:
            det = _vt_int(row.get("malicious"))
            susp = _vt_int(row.get("suspicious"))
            verdict = "%d detection%s" % (det, "" if det == 1 else "s")
            if susp:
                verdict += " · %d suspicious" % susp
            label = (row.get("label") or "").strip()
            if label:
                verdict += " · %s" % esc(label)
        if row.get("malware"):
            parts.append('<span class="vt-tf">ThreatFox: %s</span>' % esc(row["malware"]))
        if DEBUG_NO_LINKS:  # pragma: no cover - only for offline previews
            head = "<code class=\"h\">%s</code>" % h
        else:
            head = (
                '<a href="%s%s" rel="noopener noreferrer" target="_blank">'
                '<code class="h">%s</code></a>' % (VT_GUI, h, h)
            )
        items.append(
            '<li class="vt-row">%s<span class="vt-meta">%s%s</span></li>'
            % (head, verdict, " " + " ".join(parts) if parts else "")
        )

    return (
        '  <section class="card" style="margin-top:16px;">'
        "<h2>VirusTotal sample</h2>"
        '<div class="grid vt-grid">%s</div>'
        '<p class="vt-caveat">%s</p>'
        '<details class="vt-list"><summary>All %s sampled hashes (full, linked)</summary>'
        "<ul>%s</ul>"
        '<p class="sub"><a href="%s">raw VT results (JSON)</a></p>'
        "</details></section>\n"
        % (cards, caveat_html, fmt_num(stats["checked"]), "".join(items), raw_href)
    )


# ---------------------------------------------------------------------------
# History, change tracking and the trend chart
#
# The page used to show one day and forget everything else, while Output/ has
# held a daily summary since 2022. Two pieces make the history usable:
#
#   docs/history.json  - one small line per run (counts, feed health, churn).
#                        Appended by this script, never rewritten from scratch,
#                        so a bad run cannot erase the chart.
#   the delta          - "new today" and "dropped today", computed by diffing
#                        the working-tree list against HEAD. The dashboard runs
#                        BEFORE the daily commit, so HEAD still holds
#                        yesterday's published list - the same trick the
#                        staleness guard in build_lists.sh relies on.
# ---------------------------------------------------------------------------

HISTORY_KEEP = 400      # ~13 months of daily points
TREND_DAYS = 90         # window drawn on the page
LIST_FILES = ("malicious-ips.txt", "malicious-domains.txt", "malicious-hashes.txt")


def history_file(base=None):
    return (Path(base) if base else BASE) / "docs" / "history.json"


def load_history(base=None):
    """History as a list of entry dicts, oldest first; [] when there is none.

    A malformed file yields [] rather than an exception: losing the chart is
    annoying, losing the dashboard is a broken page.
    """
    path = history_file(base)
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return []
    if not isinstance(data, list):
        return []
    entries = [e for e in data if isinstance(e, dict) and e.get("date")]
    entries.sort(key=lambda e: e["date"])
    return entries[-HISTORY_KEEP:]


def save_history(entries, base=None):
    path = history_file(base)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(entries[-HISTORY_KEEP:], indent=0) + "\n",
                    encoding="utf-8")


def _git_prev_set(base, name):
    """The list as of HEAD (yesterday's published file), or None.

    None means "cannot tell" (no git, no commit yet, path never committed) and
    callers must render no delta rather than claim every indicator is new.
    """
    try:
        res = subprocess.run(
            ["git", "-C", str(base), "show", "HEAD:%s" % name],
            capture_output=True, text=True, timeout=90, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    keys = (indicator_key(ln) for ln in res.stdout.splitlines())
    return {k for k in keys if k}


# ---------------------------------------------------------------------------
# Indicator keys
#
# Churn must be counted on the INDICATOR, not on the raw line. On 2026-11-23 the
# lists gained a provenance tail ("1.0.164.165:" became "1.0.164.165:ipsum") and
# a line-level diff reported the entire corpus as new and the entire previous
# corpus as dropped - 155k/146k of noise for a format change. The rules below
# mirror the parser in lookup.js, so the page, the chart and the lookup all
# agree on what "the same indicator" means.
# ---------------------------------------------------------------------------
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,128}$")
_HOST_RE = re.compile(r"^(?=.{4,253}$)[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?"
                      r"(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)+$")
_IPV6_RE = re.compile(r"^(?=(?:[^:]*:){2,})[0-9A-Fa-f:.]+$")
# "threatfox", "ipsum", "threatfox:100|urlhaus" - feed names, an optional
# confidence before any pipe list, pipes between feeds.
_TAG_RE = re.compile(r"^[A-Za-z][\w]*(?::\d{1,3})?(?:\|[A-Za-z][\w]*(?::\d{1,3})?)*$")


def _is_indicator(text):
    if not text:
        return False
    return bool(_IPV4_RE.match(text) or _HASH_RE.match(text)
                or _HOST_RE.match(text) or _IPV6_RE.match(text))


def indicator_key(line):
    """The indicator part of one CDB line, or None for a comment/blank line."""
    v = (line or "").strip()
    if not v or v.startswith("#"):
        return None
    if v.endswith(":") and _is_indicator(v[:-1]):       # plain "1.2.3.4:"
        return v[:-1]
    if _is_indicator(v):
        return v
    # "value:source:confidence": walk colon positions right-to-left and take the
    # first whose left side is a whole indicator. Split at the FIRST such colon
    # from the right so "1.2.3.4:threatfox:100" keys on "1.2.3.4".
    i = v.rfind(":")
    while i > 0:
        head = v[:i]
        if _is_indicator(head):
            rest = v[i + 1:]
            if not rest or _TAG_RE.match(rest):
                return head
        i = v.rfind(":", 0, i)
    return v


def _current_set(path):
    path = Path(path)
    if not path.exists():
        return set()
    keys = (indicator_key(ln) for ln in
            path.read_text(encoding="utf-8", errors="ignore").splitlines())
    return {k for k in keys if k}


def churn(base=None):
    """(new, dropped) published indicators vs the previous commit, or None."""
    base = Path(base) if base else BASE
    new = dropped = 0
    known = False
    for name in LIST_FILES:
        prev = _git_prev_set(base, name)
        if prev is None:
            continue
        known = True
        cur = _current_set(base / name)
        new += len(cur - prev)
        dropped += len(prev - cur)
    return (new, dropped) if known else None


def record_history(base, day, *, ips, domains, hashes, raw, feeds_with_data,
                   feeds_total, delta):
    """Upsert today's point. Re-running the dashboard replaces the point instead
    of appending a duplicate."""
    entries = load_history(base)
    date_key = "%s-%s-%s" % (day.name[0:4], day.name[4:6], day.name[6:8])
    entry = {
        "date": date_key,
        "ips": ips,
        "domains": domains,
        "hashes": hashes,
        "published": ips + domains + hashes,
        "raw": raw if isinstance(raw, int) else None,
        "feeds_with_data": feeds_with_data,
        "feeds_total": feeds_total,
        "new": delta[0] if delta else None,
        "dropped": delta[1] if delta else None,
    }
    # A re-render must not erase churn that the run which actually published
    # measured: by then the working tree equals HEAD and the diff is 0/0.
    if delta in (None, (0, 0)):
        for prev in entries:
            if prev.get("date") == date_key and prev.get("new") is not None:
                entry["new"], entry["dropped"] = prev["new"], prev["dropped"]
                break
    entries = [e for e in entries if e.get("date") != date_key] + [entry]
    entries.sort(key=lambda e: e["date"])
    save_history(entries, base)
    return entries


def _trend_points(entries, days=TREND_DAYS):
    pts = [e for e in entries if isinstance(e.get("published"), int)]
    return pts[-days:]


def render_trend(entries, delta):
    """Inline SVG sparkline + today's churn. No JS, no chart library.

    A static SVG keeps the page a single cacheable file and works with
    JavaScript disabled; the numbers come from history.json, which grows by one
    small object per run.
    """
    pts = _trend_points(entries)
    # The stored point is authoritative for churn: it was written by the run
    # that compared today's lists with the previous commit. The live `delta`
    # only fills the gap when history has nothing recorded for the last day.
    last_entry = pts[-1] if pts else {}
    if last_entry.get("new") is not None and last_entry.get("dropped") is not None:
        new, dropped = last_entry["new"], last_entry["dropped"]
        have_churn = True
    elif delta:
        new, dropped = delta
        have_churn = True
    else:
        have_churn = False
    churn_html = ""
    if have_churn:
        churn_html = (
            '<p class="trend-note"><b class="up">+%s</b> indicators entered the '
            'lists since the last run · <b class="down">−%s</b> dropped out</p>'
            % (fmt_num(new), fmt_num(dropped))
        )
    else:
        churn_html = ('<p class="trend-note">No previous commit to compare against, '
                      'so today\'s churn is not computed.</p>')

    if len(pts) < 2:
        return (
            '<section class="card"><h2>Trend</h2>'
            '<p class="sub">History starts today — the chart fills in as the daily '
            'run adds points to <code>docs/history.json</code>.</p>%s</section>' % churn_html
        )

    vals = [e["published"] for e in pts]
    lo, hi = min(vals), max(vals)
    # 4% headroom top and bottom: the last point is drawn as a dot with a
    # stroke, and a flat range would otherwise clip it against the viewBox.
    pad_v = ((hi - lo) * 0.04) or max(1, hi * 0.01)
    lo -= pad_v
    span = (hi + pad_v) - lo or 1
    w, h, pad, pad_x = 660.0, 150.0, 8.0, 18.0
    step = (w - 2 * pad_x) / (len(vals) - 1)
    coords = []
    for i, v in enumerate(vals):
        x = pad_x + i * step
        y = h - pad - ((v - lo) / span) * (h - 2 * pad)
        coords.append((x, y))
    line = " ".join("%.1f,%.1f" % c for c in coords)
    area = line + " %.1f,%.1f %.1f,%.1f" % (coords[-1][0], h - pad, coords[0][0], h - pad)
    first, last = pts[0], pts[-1]
    change = last["published"] - first["published"]
    pct = (change / first["published"] * 100.0) if first["published"] else 0.0
    updown = "up" if change >= 0 else "down"
    sign = "+" if change >= 0 else "−"

    return (
        '<section class="card"><h2>Trend — last %d days</h2>'
        '<p class="trend-head"><b>%s</b> published indicators today, '
        '<b class="%s">%s%s</b> (%.1f%%) since %s</p>'
        '<svg class="trend" viewBox="0 0 %d %d" role="img" '
        'aria-label="Published indicator count from %s to %s, low %s, high %s">'
        '<polygon class="trend-area" points="%s"/>'
        '<polyline class="trend-line" points="%s"/>'
        '<circle class="trend-dot" cx="%.1f" cy="%.1f" r="3.5"/>'
        "</svg>"
        '<p class="trend-axis"><span>%s</span><span>%s</span></p>'
        "%s"
        '<p class="sub">Totals published after dedup and confidence filtering, '
        'one point per run.</p></section>'
        % (
            len(pts), fmt_num(last["published"]), updown,
            sign, fmt_num(abs(change)), abs(pct), first["date"],
            int(w), int(h), first["date"], last["date"], fmt_num(lo), fmt_num(hi),
            area, line, coords[-1][0], coords[-1][1], first["date"], last["date"],
            churn_html,
        )
    )


def render(day, base=None, now=None):
    """Build the dashboard HTML string for `day` (a Path to a daily folder)."""
    base = Path(base) if base else BASE
    day = Path(day)
    parsed = parse_summary(day / "daily_summary.md")
    apply_feed_config(parsed["feeds"])
    info = freshness(day, day / "daily_summary.md", now=now)

    ips = count_lines(base / "malicious-ips.txt")
    domains = count_lines(base / "malicious-domains.txt")
    hashes = count_lines(base / "malicious-hashes.txt")
    # Two different quantities, deliberately reported as two numbers:
    #   total_published - what the CDB lists actually contain (deduped, filtered)
    #   total_raw       - the collector's sum of raw feed entries, before dedup
    #                     and before the ThreatFox confidence / URLhaus domain
    #                     filters. Publishing this alone overstated the corpus
    #                     ~1.9x and read as a broken counter.
    total_published = ips + domains + hashes
    total_raw = fmt_num(parsed["total"])
    vt = vt_rows(day / "vt_enrichment.json", day / "vt_enrichment.md")

    counts = {s: 0 for s in STATUSES}
    for feed in parsed["feeds"]:
        counts[feed["status"]] = counts.get(feed["status"], 0) + 1
    n_feeds = len(parsed["feeds"])
    n_bad = counts["error"]
    n_soft = counts["empty"] + counts["unknown"]

    feed_html = "\n".join(
        '<div class="feed {status}"><b>{name}</b><span>{detail}{note}</span>'
        '<span class="tag">{tag}</span></div>'.format(
            status=f["status"],
            name=esc(f["name"]),
            detail=esc(f["detail"]),
            note=(
                ' <em class="feed-note">— %s</em>' % esc(f["note"])
                if f.get("note")
                else ""
            ),
            tag="expected empty" if f["status"] == "expected" else f["status"],
        )
        for f in parsed["feeds"]
    ) or "<p>No feed summary found.</p>"

    vt_section = render_vt_section(vt, day)

    if info["stale"]:
        if not info["is_today"]:
            reason = (
                "no output folder exists for today - the scheduled run did not "
                "produce one"
            )
        else:
            reason = "today's summary is older than %d h" % STALE_AFTER_HOURS
        banner = (
            '<div class="banner stale"><b>STALE DATA</b> — showing '
            f"{info['data_date']:%Y-%m-%d}, not today. {esc(reason)}. "
            "Do not treat these counts as current.</div>"
        )
    else:
        banner = ""

    generated = (
        info["generated"].strftime("%Y-%m-%d %H:%M %Z") if info["generated"] else "unknown"
    )
    age_text = _age_text(info["age_hours"])

    # The feed card must never describe itself with a claim the neighbouring
    # numbers contradict: "5/6 feeds with data" sat next to the label "all
    # feeds reported data" whenever a feed came back empty-but-expected
    # (Feodo after Operation Endgame), because "expected" counted as neither
    # failed nor soft. The note now names exactly what is missing, and its
    # colour is driven by the worst status present.
    ok_n, total_n = n_feeds - n_bad - n_soft - counts["expected"], n_feeds
    if n_bad:
        feed_card_class = "card bad"
        feed_note = "%d failed" % n_bad
    elif n_soft:
        feed_card_class = "card warn"
        feed_note = "%d empty/unknown" % n_soft
    elif counts["expected"]:
        feed_card_class = "card"
        names = ", ".join(f["name"] for f in parsed["feeds"] if f["status"] == "expected")
        feed_note = "%d expected empty (%s)" % (counts["expected"], names)
    else:
        feed_card_class = "card"
        feed_note = "all feeds reported data"
    feed_sub = feed_note

    meta_counts = "%s indicators from %s sources" % (
        fmt_num(total_published), "open threat-intel feeds")
    meta_description = (
        "Daily, deduplicated indicators of compromise from six public "
        "threat-intelligence feeds, republished as checksummed Wazuh CDB lists, "
        "with a lookup tool and feed-health dashboard. Data for %s."
        % info["data_date"].strftime("%Y-%m-%d")
    )

    # One segment per feed, coloured by its status: the shape of the day is
    # readable at a glance, and a glance is all this card gets.
    feed_dots = "".join(
        '<i class="dot %s" title="%s"></i>' % (feed["status"], esc(feed["name"]))
        for feed in parsed["feeds"]
    )

    # Trend needs history plus today's point; render() stays self-contained so a
    # test or a one-off run renders a sane page without main() recording anything.
    delta = churn(base)
    entries = load_history(base)
    date_key = "%s-%s-%s" % (day.name[0:4], day.name[4:6], day.name[6:8])
    if not entries or entries[-1].get("date") != date_key:
        entries = entries + [{"date": date_key, "published": total_published}]
    trend_html = render_trend(entries, delta)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OpenIOCCollector — daily IOC list, {info['data_date']:%Y-%m-%d}</title>
<meta name="description" content="{esc(meta_description)}">
<meta name="theme-color" content="#0b1220">
<link rel="canonical" href="{PAGES_URL}/">
<link rel="icon" href="favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="og.png">
<meta property="og:type" content="website">
<meta property="og:site_name" content="OpenIOCCollector">
<meta property="og:title" content="OpenIOCCollector — {esc(meta_counts)}">
<meta property="og:description" content="{esc(meta_description)}">
<meta property="og:url" content="{PAGES_URL}/">
<meta property="og:image" content="{PAGES_URL}/og.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="OpenIOCCollector — {esc(meta_counts)}">
<meta name="twitter:description" content="{esc(meta_description)}">
<meta name="twitter:image" content="{PAGES_URL}/og.png">
<style>
  :root {{
    --bg:#0b1220; --card:#121a2b; --line:#243049; --text:#e8eefc;
    --muted:#9aa8c7; --ok:#3ddc97; --bad:#ff6b6b; --warn:#f5a524; --accent:#6ea8fe;
  }}
  * {{ box-sizing:border-box; }}
  body {{
    margin:0; font-family:Verdana, Geneva, sans-serif; background:var(--bg); color:var(--text);
  }}
  header, main {{ max-width:1100px; margin:0 auto; padding:24px; }}
  header {{ padding-top:36px; }}
  h1 {{ margin:0 0 8px; font-size:28px; }}
  .sub {{ color:var(--muted); }}
  .banner {{ border-radius:12px; padding:14px 16px; margin:18px 0 0; font-size:14px; }}
  .banner.stale {{ background:#3a2410; border:1px solid var(--warn); color:#ffd79a; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:16px; margin:24px 0; }}
  .card {{ background:var(--card); border:1px solid var(--line); border-radius:14px; padding:18px; }}
  .card.bad {{ border-color:var(--bad); }}
  .card.warn {{ border-color:var(--warn); }}
  .num {{ font-size:28px; font-weight:700; }}
  .label {{ color:var(--muted); margin-top:6px; font-size:13px; }}
  .feeds {{ display:grid; gap:10px; }}
  .feed {{ display:flex; align-items:baseline; gap:12px; background:#0f1726; padding:12px 14px; border-radius:10px; }}
  .feed b {{ flex:0 0 210px; }}
  .feed span {{ flex:1 1 auto; color:var(--muted); }}
  .feed .tag {{ flex:0 0 auto; font-size:11px; letter-spacing:.08em; text-transform:uppercase; }}
  .feed.ok {{ border-left:4px solid var(--ok); }}
  .feed.ok .tag {{ color:var(--ok); }}
  .feed.empty {{ border-left:4px solid var(--warn); }}
  .feed.empty .tag {{ color:var(--warn); }}
  .feed.unknown {{ border-left:4px solid var(--warn); }}
  .feed.unknown .tag {{ color:var(--warn); }}
  .feed.error {{ border-left:4px solid var(--bad); background:#1c1215; }}
  .feed.error .tag {{ color:var(--bad); font-weight:700; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th, td {{ text-align:left; padding:10px 8px; border-bottom:1px solid var(--line); }}
  th {{ color:var(--muted); font-weight:600; }}
  .hash {{ font-family:monospace; }}
  .feed.expected {{ border-left:4px solid #3a4763; }}
  .feed.expected .tag {{ color:var(--muted); }}
  .feed-note {{ color:var(--muted); font-size:12px; font-style:normal; }}
  .vt-grid {{ margin:16px 0 10px; }}
  .vt-caveat {{ color:var(--muted); font-size:12.5px; line-height:1.6; margin:0 0 12px; }}
  .vt-caveat span {{ display:inline; }}
  .vt-list summary {{ cursor:pointer; font-size:13px; color:var(--accent); }}
  .vt-list ul {{ list-style:none; padding:0; margin:12px 0 0; }}
  .vt-row {{ padding:9px 0; border-bottom:1px solid var(--line); }}
  .vt-row code.h {{ font-family:monospace; font-size:12px; word-break:break-all; }}
  .vt-meta {{ display:block; color:var(--muted); font-size:12px; margin-top:3px; }}
  .vt-tf {{ color:var(--text); }}
  a {{ color:var(--accent); }}
  .lookup {{ display:flex; gap:10px; margin:16px 0 6px; }}
  .lookup input {{ flex:1 1 auto; min-width:0; background:#0f1726; border:1px solid var(--line);
                   color:var(--text); border-radius:10px; padding:11px 13px; font-size:15px; font-family:inherit; }}
  .lookup input::placeholder {{ color:#6b7a99; }}
  .lookup input:focus {{ outline:2px solid var(--accent); outline-offset:1px; }}
  .lookup button {{ flex:0 0 auto; background:var(--accent); color:#06101f; border:0; border-radius:10px;
                    padding:11px 18px; font-size:15px; font-weight:700; font-family:inherit; cursor:pointer; }}
  .lookup button:hover {{ filter:brightness(1.08); }}
  .hint {{ color:var(--muted); font-size:12.5px; line-height:1.5; margin:0 0 10px; }}
  .status {{ font-size:13px; color:var(--muted); min-height:1.5em; }}
  .status.err {{ color:var(--bad); }}
  .result {{ margin-top:12px; border-radius:10px; padding:14px 16px; background:#0f1726; border-left:4px solid var(--line); }}
  .result.hit {{ border-left-color:var(--bad); }}
  .result.hit.low {{ border-left-color:var(--warn); }}
  .result.miss {{ border-left-color:var(--ok); }}
  .result .verdict {{ font-weight:700; font-size:16px; }}
  .result.hit .verdict {{ color:var(--bad); }}
  .result.hit.low .verdict {{ color:var(--warn); }}
  .result.miss .verdict {{ color:var(--ok); }}
  .result .val {{ font-family:monospace; word-break:break-all; font-size:14px; margin-top:3px; }}
  .result dl {{ display:grid; grid-template-columns:auto 1fr; gap:4px 14px; margin:11px 0 0; font-size:13px; }}
  .result dt {{ color:var(--muted); }}
  .result dd {{ margin:0; word-break:break-all; }}
  .result .hint {{ margin:11px 0 0; }}
  .sr-only {{ position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden;
              clip:rect(0 0 0 0); white-space:nowrap; border:0; }}
  .kpi-sub {{ color:var(--muted); font-size:11.5px; margin-top:4px; }}
  .feed-dots {{ display:flex; gap:4px; margin-top:10px; }}
  .dot {{ display:block; height:4px; flex:1 1 0; border-radius:2px; background:#2a3550; }}
  .dot.ok {{ background:var(--ok); }}
  .dot.empty, .dot.unknown {{ background:var(--warn); }}
  .dot.expected {{ background:#4a5b7d; }}
  .dot.error {{ background:var(--bad); }}
  .trend {{ width:100%; height:auto; display:block; margin:16px 0 4px; }}
  .trend-line {{ fill:none; stroke:var(--accent); stroke-width:2; vector-effect:non-scaling-stroke; }}
  .trend-area {{ fill:rgba(110,168,254,.12); stroke:none; }}
  .trend-dot {{ fill:var(--text); stroke:var(--accent); stroke-width:2; }}
  .trend-head {{ margin:4px 0 0; font-size:14px; }}
  .trend-axis {{ display:flex; justify-content:space-between; color:var(--muted); font-size:12px; margin:0; }}
  .trend-note {{ margin:12px 0 0; font-size:13px; color:var(--muted); }}
  .up {{ color:var(--ok); }} .down {{ color:var(--warn); }}
  code {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12.5px; }}
  @media (max-width:560px) {{
    .grid {{ grid-template-columns:repeat(2,1fr); gap:12px; margin:18px 0; }}
    .num {{ font-size:23px; }}
    .card, .feed {{ padding:14px; }}
    .feed {{ flex-wrap:wrap; }}
    .feed b {{ flex:1 1 100%; }}
    header, main {{ padding:18px; }}
    .lookup {{ flex-direction:column; }}
    .lookup button {{ width:100%; }}
  }}
</style>
</head>
<body>
<header>
  <h1>OpenIOCCollector</h1>
  <p class="sub">Daily IOC dashboard · data for <b>{info['data_date']:%Y-%m-%d}</b>
     · generated {esc(generated)} ({esc(age_text)})</p>
  {banner}
</header>
<main>
  <section class="grid">
    <div class="card"><div class="num">{ips:,}</div><div class="label">Malicious IPs</div></div>
    <div class="card"><div class="num">{domains:,}</div><div class="label">Malicious domains</div></div>
    <div class="card"><div class="num">{hashes:,}</div><div class="label">Malicious hashes</div></div>
    <div class="{feed_card_class}"><div class="num">{ok_n}/{total_n}</div>
      <div class="label">feeds reporting</div>
      <div class="kpi-sub">{esc(feed_note)}</div>
      <div class="feed-dots">{feed_dots}</div></div>
  </section>

{trend_html}
{lookup_section()}  <section class="card">
    <h2>Feeds — {info['data_date']:%Y-%m-%d}</h2>
    <div class="feeds">{feed_html}</div>
    <p class="sub">Collector clock at run: {esc(parsed['run_label'])} · {n_feeds} feeds checked
       · <b>{total_published:,} unique IOCs published</b>
         ({ips:,} IPs + {domains:,} domains + {hashes:,} hashes)
         from {esc(total_raw)} raw feed entries before dedup and confidence filtering</p>
  </section>

{vt_section}
  <p style="margin-top:24px;">
    <a href="{REPO}">GitHub repository</a> ·
    <a href="{REPO}/releases/tag/iocs-{day.name}">Raw dumps for {info['data_date']:%Y-%m-%d}</a> ·
    <a href="api/manifest.json" title="counts, feed status and SHA-256 of every published list">API manifest</a> ·
    <a href="history.json" title="one point per run, the source of the trend chart">history</a>
  </p>
</main>
{lookup_script(info, ips, domains, hashes)}
</body>
</html>
"""
    return html


def _sha256(path):
    path = Path(path)
    if not path.exists():
        return None
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _last_churn(base):
    """Today's entered/dropped counts, straight from the recorded point.

    The point is written by the run that compared today's lists with the
    previous commit, so it is the measured value - not a re-derived one.
    """
    entries = load_history(base)
    if not entries:
        return None
    last = entries[-1]
    if last.get("new") is None:
        return None
    return {"date": last.get("date"),
            "entered": last["new"],
            "dropped": last.get("dropped")}


def build_manifest(base=None, day=None, now=None):
    """docs/api/manifest.json - what a machine consumer needs, in one request.

    Deliberately NOT a JSON copy of 155k indicators: that would be an ~18 MB
    file rewritten every day, which is the same unbounded-git-growth problem
    SIZE_FIX.md documents for the raw dumps. The CDB lists stay the payload;
    this file tells a consumer what is in them, how fresh they are, and how to
    verify what they downloaded.
    """
    base = Path(base) if base else BASE
    day = Path(day) if day else latest_day_dir(base)[0]
    parsed = parse_summary(day / "daily_summary.md")
    apply_feed_config(parsed["feeds"])

    counts = {key: count_lines(base / name)
              for key, name in zip(("ips", "domains", "hashes"), LIST_FILES)}
    counts["published"] = sum(counts.values())
    raw = parsed["total"]
    success = parsed["success"]
    ok_n = total_n = None
    m = re.match(r"(\d+)\s*/\s*(\d+)", str(success))
    if m:
        ok_n, total_n = int(m.group(1)), int(m.group(2))

    files = {}
    for name in LIST_FILES:
        path = base / name
        files[name] = {
            "entries": count_lines(path),
            "bytes": path.stat().st_size if path.exists() else 0,
            "sha256": _sha256(path),
            "url": "%s/%s" % (REPO_RAW, name),
        }

    manifest = {
        "schema": 1,
        "generated_at": (now or datetime.now().astimezone()).astimezone()
                        .isoformat(timespec="seconds"),
        "data_date": datetime.strptime(day.name, "%Y%m%d").date().isoformat(),
        "counts": counts,
        "raw_entries": int(raw) if str(raw).strip().isdigit() else None,
        "feeds": [{"name": f["name"], "status": f["status"], "detail": f["detail"]}
                  for f in parsed["feeds"]],
        "feeds_with_data": ok_n,
        "feeds_total": total_n,
        "churn": _last_churn(base),
        "files": files,
        "format": {
            "encoding": "utf-8",
            "line": "<indicator>[:<feeds>[|<feeds>...][:<confidence>]]",
            "notes": ("CDB list: the key is the whole indicator; an optional "
                      "tail carries provenance so the same file can answer "
                      "'which feed, at what confidence'. Wazuh matches keys "
                      "only, so the tail never changes what a rule catches."),
        },
        "history": "%s/history.json" % PAGES_URL,
        "repo": REPO,
        "docs": "%s/" % PAGES_URL,
        "license": "GPL-3.0-or-later",
    }
    api_dir = base / "docs" / "api"
    api_dir.mkdir(parents=True, exist_ok=True)
    (api_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main(base=None, out=None, now=None):
    base = Path(base) if base else BASE
    day, _is_today = latest_day_dir(base)

    # Record the point before rendering, so the page's own trend includes today.
    parsed = parse_summary(day / "daily_summary.md")
    raw = parsed["total"]
    m = re.match(r"(\d+)\s*/\s*(\d+)", str(parsed["success"]))
    record_history(
        base, day,
        ips=count_lines(base / "malicious-ips.txt"),
        domains=count_lines(base / "malicious-domains.txt"),
        hashes=count_lines(base / "malicious-hashes.txt"),
        raw=int(raw) if str(raw).strip().isdigit() else None,
        feeds_with_data=int(m.group(1)) if m else None,
        feeds_total=int(m.group(2)) if m else None,
        delta=churn(base),
    )
    build_manifest(base, day, now=now)

    html = render(day, base=base, now=now)
    out = Path(out) if out else (base / "docs" / "index.html")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    print(f"Wrote {out} (data folder {day})")
    return 0


if __name__ == "__main__":
    main()
