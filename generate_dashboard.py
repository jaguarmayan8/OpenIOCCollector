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
import json
import re
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

    if n_bad:
        feed_card_class, feed_sub = "card bad", f"{n_bad} failed"
    elif n_soft:
        feed_card_class, feed_sub = "card warn", f"{n_soft} empty/unknown"
    else:
        feed_card_class, feed_sub = "card", "all feeds reported data"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OpenIOCCollector Dashboard — {info['data_date']:%Y-%m-%d}</title>
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
  @media (max-width:560px) {{ .lookup {{ flex-direction:column; }} .lookup button {{ width:100%; }} }}
</style>
</head>
<body>
<header>
  <h1>OpenIOCCollector</h1>
  <p class="sub">Home-lab threat intel dashboard · data for <b>{info['data_date']:%Y-%m-%d}</b>
     · generated {esc(generated)} ({esc(age_text)})</p>
  {banner}
</header>
<main>
  <section class="grid">
    <div class="card"><div class="num">{ips:,}</div><div class="label">Malicious IPs</div></div>
    <div class="card"><div class="num">{domains:,}</div><div class="label">Malicious domains</div></div>
    <div class="card"><div class="num">{hashes:,}</div><div class="label">Malicious hashes</div></div>
    <div class="{feed_card_class}"><div class="num">{esc(parsed['success'])}</div>
      <div class="label">Feeds with data ({esc(feed_sub)})</div></div>
  </section>

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
    <a href="{REPO}/releases/tag/iocs-{day.name}">Raw dumps for {info['data_date']:%Y-%m-%d}</a>
  </p>
</main>
{lookup_script(info, ips, domains, hashes)}
</body>
</html>
"""
    return html


def main(base=None, out=None, now=None):
    base = Path(base) if base else BASE
    day, _is_today = latest_day_dir(base)
    html = render(day, base=base, now=now)
    out = Path(out) if out else (base / "docs" / "index.html")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    print(f"Wrote {out} (data folder {day})")
    return 0


if __name__ == "__main__":
    main()
