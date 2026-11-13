#!/usr/bin/env python3
"""
IOC Collector - daily threat intel feed downloader.

IMPORTANT (2026-11): abuse.ch now requires an Auth-Key for data exports.
Keyless download URLs answer HTTP 410 Gone. This collector authenticates:

  - URLhaus:     Auth-Key embedded in the export URL path
                 https://urlhaus-api.abuse.ch/v2/files/exports/<KEY>/<file>
                 (docs: https://urlhaus.abuse.ch/api/)
  - ThreatFox:   Auth-Key HTTP header on the JSON API
                 POST https://threatfox-api.abuse.ch/api/v1/ {"query": "get_iocs", "days": N}
                 (docs: https://threatfox.abuse.ch/api/)
  - MalwareBazaar: Auth-Key header on the POST API (unchanged from before)

Get one free key at https://auth.abuse.ch/ and store it in .abusech_auth_key
next to this script. The SAME key works for all abuse.ch platforms.

Output files and the daily_summary.md format are kept identical to the old
version so run_andpush.sh, vt_enrich.py and generate_dashboard.py keep working.
"""

import csv
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter, Retry

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
)
log = logging.getLogger("ioc-collector")

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

BASE = Path(__file__).resolve().parent
ABUSECH_KEY_FILE = BASE / ".abusech_auth_key"

REQUEST_TIMEOUT = 45
USER_AGENT = "OpenIOCCollector/2.0 (home-lab threat intel collector)"

# URLhaus export file to download. "recent.csv" is the example documented at
# https://urlhaus.abuse.ch/api/ . The API page also offers other dump
# variants (full dump, active sites only, past-30-days; CSV and JSON) -
# check the exact file names listed there if you want a different slice.
URLHAUS_EXPORT_FILE = "recent.csv"

# ThreatFox get_iocs: number of days to filter IOCs by first_seen.
# API allows Min 1, Max 7. (The old /export/json/recent/ file covered the
# most recent window; 7 days keeps the hash/domain pipeline well fed.)
THREATFOX_DAYS = 7

# MalwareBazaar get_recent sample count.
MALWAREBAZAAR_LIMIT = 100

# Exit with error if fewer than this many feeds returned data.
MIN_SUCCESSFUL_FEEDS = 2


def load_auth_key() -> str:
    """Read the abuse.ch Auth-Key. Same key works for URLhaus/ThreatFox/MalwareBazaar."""
    if not ABUSECH_KEY_FILE.exists():
        log.error(
            "Missing %s - abuse.ch exports now REQUIRE an Auth-Key. "
            "Create one free at https://auth.abuse.ch/ and save it in that file.",
            ABUSECH_KEY_FILE.name,
        )
        return ""
    key = ABUSECH_KEY_FILE.read_text(encoding="utf-8").strip()
    if not key:
        log.error("%s exists but is empty", ABUSECH_KEY_FILE.name)
    return key


def make_session() -> requests.Session:
    """Session with retry/backoff and a proper User-Agent (some feeds throttle
    the default python-requests UA)."""
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=2,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST"]),
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({"User-Agent": USER_AGENT})
    return session


# --------------------------------------------------------------------------
# Feed handlers - each saves the file and returns (ioc_count or None on error)
# --------------------------------------------------------------------------

def fetch_file(session: requests.Session, path: Path, url: str, skip_header: bool = False):
    """Plain HTTP download (sslbl, feodo, ipsum). Line-based IOC count,
    skipping '#' comment lines and optionally the first header line of CSVs."""
    r = session.get(url, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    path.write_bytes(r.content)

    text = r.content.decode("utf-8", errors="ignore")
    lines = [
        line for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    ]
    if skip_header and lines:
        # First non-comment line of these CSVs is a column header (e.g. "sha1"),
        # not an IOC - don't count it.
        lines = lines[1:]
    return len(lines)


def fetch_urlhaus(session: requests.Session, path: Path, auth_key: str):
    """URLhaus malware URL dump, downloaded with the Auth-Key in the URL path.

    Note: the key travels in the URL itself (that is how abuse.ch's key-in-path
    auth works), so avoid logging the full URL.
    """
    url = f"https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/{URLHAUS_EXPORT_FILE}"
    r = session.get(url, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    path.write_bytes(r.content)

    # Parse the CSV properly instead of counting raw lines: skip comment
    # lines, the header row, and blank lines.
    text = r.content.decode("utf-8", errors="ignore")
    rows = 0
    reader = csv.reader(
        line for line in text.splitlines() if line.strip() and not line.startswith("#")
    )
    for i, row in enumerate(reader):
        if i == 0:
            continue  # header row
        if row:
            rows += 1
    return rows


def fetch_threatfox(session: requests.Session, path: Path, auth_key: str):
    """ThreatFox recent IOCs via the authenticated JSON API.

    Saved as {"iocs": [...]} so the existing downstream scripts keep working:
    run_andpush.sh and vt_enrich.py both iterate data.values() -> list of IOC
    dicts, which is exactly what the old export file looked like. An empty
    result is still written to disk so the pipeline never crashes on a
    missing file (today's 410 bug broke the hash extraction that way).
    """
    r = session.post(
        "https://threatfox-api.abuse.ch/api/v1/",
        headers={"Auth-Key": auth_key},
        # ThreatFox requires the request body to be a JSON document (its docs
        # show: -d '{"query": "get_iocs", "days": 7}'). Sending form-encoded
        # data (data=...) makes the API answer query_status="no_json".
        # MalwareBazaar is different - its API reads form fields, which is why
        # fetch_malwarebazaar below uses data=.
        json={"query": "get_iocs", "days": THREATFOX_DAYS},
        timeout=REQUEST_TIMEOUT,
    )
    r.raise_for_status()
    payload = r.json()
    status = payload.get("query_status")
    raw_data = payload.get("data")
    # Only a list is real IOC data - on errors like no_json, "data" is an
    # error STRING, and len() of it must not be counted as IOCs.
    data = raw_data if isinstance(raw_data, list) else []
    if status != "ok":
        # e.g. "no_results" is a valid empty answer, anything else is a problem
        log.warning("ThreatFox API returned query_status=%s", status)
    # Persist in the dict-of-lists shape the downstream scripts expect.
    path.write_text(json.dumps({"iocs": data}, indent=2), encoding="utf-8")
    return len(data)


def fetch_malwarebazaar(session: requests.Session, path: Path, auth_key: str):
    """MalwareBazaar recent samples (hashes + metadata, no binaries). Unchanged
    from the previous version apart from retries/logging."""
    r = session.post(
        "https://mb-api.abuse.ch/api/v1/",
        headers={"Auth-Key": auth_key},
        data={"query": "get_recent", "selector": str(MALWAREBAZAAR_LIMIT)},
        timeout=REQUEST_TIMEOUT,
    )
    r.raise_for_status()
    payload = r.json()
    rows = payload.get("data") or []
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if payload.get("query_status") == "ok":
        return len(rows)
    log.warning("MalwareBazaar query_status=%s", payload.get("query_status"))
    return 0


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main() -> int:
    print("=== IOC Collector Started ===")
    now = datetime.now()
    today = now.strftime("%Y%m%d")
    year = now.strftime("%Y")
    year_month = now.strftime("%Y-%m")

    output_dir = BASE / "Output" / year / year_month / today
    output_dir.mkdir(parents=True, exist_ok=True)

    auth_key = load_auth_key()

    # (filename, kind, url, skip_header) - kind selects the handler.
    # NOTE: if sslbl starts returning 410 too, check https://sslbl.abuse.ch/
    # for its authenticated export URL and add a kind="auth_file" handler.
    plain_feeds = [
        ("ssl_blacklist.csv",
         "https://sslbl.abuse.ch/blacklist/sslblacklist.csv", False),
        # Feodo Tracker is currently empty due to successful takedowns
        ("feodo_tracker.txt",
         "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", False),
        ("top_malicious.txt",
         "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt", False),
    ]

    summary = [f"# Daily IOC Report - {now.strftime('%Y-%m-%d %H:%M')}", ""]
    success_count = 0
    total_iocs = 0

    def record(name: str, ok: bool, detail: str, ioc_count: int):
        nonlocal success_count, total_iocs
        total_iocs += ioc_count
        if ok:
            success_count += 1
            summary.append(f"- **{name}**: {detail}")
            log.info("%s: %s", name, detail)
        else:
            summary.append(f"- **{name}**: {detail}")
            log.warning("%s: %s", name, detail)

    session = make_session()

    # --- plain file downloads -------------------------------------------------
    for filename, url, skip_header in plain_feeds:
        path = output_dir / filename
        try:
            count = fetch_file(session, path, url, skip_header=skip_header)
            size_kb = path.stat().st_size / 1024
            if size_kb < 1:
                record(filename, False,
                       f"Empty ({size_kb:.1f} KB) - this may be expected", 0)
            else:
                record(filename, True,
                       f"{size_kb:.1f} KB | ~{count} entries", count)
        except Exception as e:
            record(filename, False, f"Error - {e}", 0)

    # --- URLhaus (authenticated export) --------------------------------------
    try:
        if auth_key:
            path = output_dir / "urlhaus.csv"
            count = fetch_urlhaus(session, path, auth_key)
            size_kb = path.stat().st_size / 1024
            record("urlhaus.csv", True, f"{size_kb:.1f} KB | ~{count} entries", count)
        else:
            record("urlhaus.csv", False, "Error - no Auth-Key (.abusech_auth_key missing)", 0)
    except Exception as e:
        record("urlhaus.csv", False, f"Error - {e}", 0)

    # --- ThreatFox (authenticated API) ----------------------------------------
    try:
        if auth_key:
            path = output_dir / "threatfox_recent.json"
            count = fetch_threatfox(session, path, auth_key)
            size_kb = path.stat().st_size / 1024
            if count:
                record("threatfox_recent.json", True,
                       f"{size_kb:.1f} KB | ~{count} entries", count)
            else:
                record("threatfox_recent.json", False,
                       f"Empty (query_status or no results in last {THREATFOX_DAYS}d)", 0)
        else:
            record("threatfox_recent.json", False,
                   "Error - no Auth-Key (.abusech_auth_key missing)", 0)
    except Exception as e:
        # Still write an empty-but-valid file so run_andpush.sh's hash
        # extraction and vt_enrich.py can't crash on a missing file.
        (output_dir / "threatfox_recent.json").write_text(
            json.dumps({"iocs": []}, indent=2), encoding="utf-8")
        record("threatfox_recent.json", False, f"Error - {e}", 0)

    # --- MalwareBazaar (authenticated API) ------------------------------------
    try:
        if auth_key:
            path = output_dir / "malwarebazaar_recent.json"
            count = fetch_malwarebazaar(session, path, auth_key)
            size_kb = path.stat().st_size / 1024
            if count:
                record("malwarebazaar_recent.json", True,
                       f"{size_kb:.1f} KB | ~{count} entries", count)
            else:
                record("malwarebazaar_recent.json", False, "Empty (no samples)", 0)
        else:
            record("malwarebazaar_recent.json", False,
                   "Error - no Auth-Key (.abusech_auth_key missing)", 0)
    except Exception as e:
        record("malwarebazaar_recent.json", False, f"Error - {e}", 0)

    # --- summary report --------------------------------------------------------
    feed_total = len(plain_feeds) + 3  # urlhaus, threatfox, malwarebazaar
    report_path = output_dir / "daily_summary.md"
    with open(report_path, "w") as f:
        f.write("\n".join(summary))
        f.write(f"\n\n**Success rate:** {success_count}/{feed_total} feeds with data")
        f.write(f"\n**Approximate total IOCs collected:** {total_iocs}")

    print(f"\n[+] Files saved to: {output_dir}")
    print(f"[+] Summary report saved: {report_path.name}")
    print(f"[+] Feeds with data: {success_count}/{feed_total}")
    print("=== IOC Collector Finished ===")

    if success_count < MIN_SUCCESSFUL_FEEDS:
        print("[!] Too many failures - exiting with error")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
