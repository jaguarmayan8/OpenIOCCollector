#!/usr/bin/env python3
"""
normalize.py — turn raw daily IOC dumps into typed, deduped lists.

Run AFTER tweetfeed.py:

    python3 tweetfeed.py
    python3 normalize.py

Looks under Output/YYYY/YYYY-MM/YYYYMMDD/ for:
    urlhaus.csv
    threatfox_recent.json
    ssl_blacklist.csv
    feodo_tracker.txt
    top_malicious.txt   (also accepts top_malicious.csv)

Writes into that same day folder:
    ips.txt  domains.txt  urls.txt  hashes.txt  ssl_sha1.txt
    manifest.json
    daily_normalized.md

Also copies latest.json to:
    ./latest.json
    ./site/data/latest.json   (created if missing)
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import ipaddress
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Optional whitelist (same names as whitelist.py in this repo)
# ---------------------------------------------------------------------------
try:
    from whitelist import (  # type: ignore
        whitelist_domains,
        whitelist_ips,
        whitelist_urls,
    )
except Exception:
    whitelist_domains = ["example.com", "google.com", "twitter.com", "x.com", "t.co"]
    whitelist_ips = ["1.1.1.1", "8.8.8.8"]
    whitelist_urls = ["https://favicon.ico", "http://test.test"]

# IPsum: keep rows seen on this many blocklists (3 = default IPsum "level 3")
IPSUM_MIN_SCORE = 3

FEED_FILES = {
    "urlhaus": ["urlhaus.csv"],
    "threatfox": ["threatfox_recent.json"],
    "sslbl": ["ssl_blacklist.csv"],
    "feodo": ["feodo_tracker.txt", "feodo_tracker.csv"],
    "ipsum": ["top_malicious.txt", "top_malicious.csv"],
}

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def host_from_url(url: str) -> str | None:
    try:
        parsed = urlparse(url.strip())
    except Exception:
        return None
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    return host or None


def strip_port(ioc: str) -> str:
    """ip:port → ip ; leave bare IPs alone."""
    ioc = ioc.strip()
    if ioc.count(":") == 1:
        left, right = ioc.rsplit(":", 1)
        if right.isdigit() and IPV4_RE.fullmatch(left):
            return left
    return ioc


def normalize_url(url: str) -> str | None:
    url = url.strip().strip('"')
    if not url or url.startswith("#"):
        return None
    if not re.match(r"^https?://", url, re.I):
        return None
    return url


def find_day_dir(output_root: Path, explicit: str | None) -> Path:
    if explicit:
        p = Path(explicit)
        if not p.is_dir():
            raise SystemExit(f"Day directory not found: {p}")
        return p

    dated = []
    if output_root.is_dir():
        for child in output_root.rglob("*"):
            if child.is_dir() and re.fullmatch(r"\d{8}", child.name):
                dated.append(child)
    if dated:
        return sorted(dated, key=lambda p: p.name)[-1]

    raise SystemExit(
        f"No YYYYMMDD folder under {output_root}. Run tweetfeed.py first."
    )


def load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def csv_rows_skipping_comments(text: str):
    cleaned = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        cleaned.append(line)
    if not cleaned:
        return []
    reader = csv.reader(io.StringIO("\n".join(cleaned)))
    rows = list(reader)
    if rows and rows[0] and any("id" in c.lower() or "sha1" in c.lower() or "first_seen" in c.lower() for c in rows[0]):
        return rows[1:]
    return rows


class Buckets:
    def __init__(self) -> None:
        self.ips: set[str] = set()
        self.domains: set[str] = set()
        self.urls: set[str] = set()
        self.hashes: set[str] = set()
        self.ssl_sha1: set[str] = set()
        self.wl_dropped = Counter()
        self.source_counts = Counter()

    def add_ip(self, raw: str, source: str) -> None:
        ip = strip_port(raw.strip())
        if not is_public_ip(ip):
            return
        if ip in whitelist_ips:
            self.wl_dropped["ip"] += 1
            return
        self.ips.add(ip)
        self.source_counts[f"{source}:ip"] += 1

    def add_domain(self, raw: str, source: str) -> None:
        dom = raw.strip().lower().rstrip(".")
        if not dom or " " in dom:
            return
        if not DOMAIN_RE.fullmatch(dom):
            return
        # skip raw IPv4 mistaken as domain
        if IPV4_RE.fullmatch(dom):
            self.add_ip(dom, source)
            return
        if any(dom == w or dom.endswith("." + w) for w in whitelist_domains):
            self.wl_dropped["domain"] += 1
            return
        self.domains.add(dom)
        self.source_counts[f"{source}:domain"] += 1

    def add_url(self, raw: str, source: str) -> None:
        url = normalize_url(raw)
        if not url:
            return
        if url in whitelist_urls:
            self.wl_dropped["url"] += 1
            return
        host = host_from_url(url)
        if host and any(host == w or host.endswith("." + w) for w in whitelist_domains):
            self.wl_dropped["url"] += 1
            return
        self.urls.add(url)
        self.source_counts[f"{source}:url"] += 1
        if host:
            if IPV4_RE.fullmatch(host):
                self.add_ip(host, source)
            else:
                self.add_domain(host, source)

    def add_hash(self, raw: str, source: str) -> None:
        h = raw.strip().lower()
        if not (MD5_RE.fullmatch(h) or SHA1_RE.fullmatch(h) or SHA256_RE.fullmatch(h)):
            return
        self.hashes.add(h)
        self.source_counts[f"{source}:hash"] += 1

    def add_ssl(self, raw: str, source: str) -> None:
        h = raw.strip().lower()
        if not SHA1_RE.fullmatch(h):
            return
        self.ssl_sha1.add(h)
        self.source_counts[f"{source}:ssl_sha1"] += 1


def parse_urlhaus(path: Path, buckets: Buckets) -> dict:
    text = load_text(path)
    rows = csv_rows_skipping_comments(text)
    raw = 0
    for row in rows:
        if len(row) < 3:
            continue
        # id, dateadded, url, ...
        url = row[2].strip().strip('"')
        if not url.startswith("http"):
            # header-less / shifted row: find first http field
            url = next((c for c in row if c.strip().startswith("http")), "")
        if not url:
            continue
        raw += 1
        buckets.add_url(url, "urlhaus")
    return {"raw_rows": raw, "status": "ok" if raw else "empty"}


def iter_threatfox_items(data):
    """ThreatFox recent JSON is usually {ioc_id: [ {ioc, ioc_type, ...}, ... ]}."""
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                yield item
        return
    if isinstance(data, dict):
        # skip query_status wrapper if present
        if "data" in data and isinstance(data["data"], (list, dict)):
            yield from iter_threatfox_items(data["data"])
            return
        for value in data.values():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        yield item
            elif isinstance(value, dict) and ("ioc" in value or "ioc_value" in value):
                yield value


def parse_threatfox(path: Path, buckets: Buckets) -> dict:
    try:
        data = json.loads(load_text(path))
    except json.JSONDecodeError as exc:
        return {"raw_rows": 0, "status": "error", "error": f"invalid json: {exc}"}

    raw = 0
    types = Counter()
    for item in iter_threatfox_items(data):
        ioc = (item.get("ioc") or item.get("ioc_value") or "").strip()
        ioc_type = (item.get("ioc_type") or item.get("type") or "").strip().lower()
        if not ioc:
            continue
        raw += 1
        types[ioc_type or "unknown"] += 1

        if ioc_type in {"ip:port", "ip", "ipv4"}:
            buckets.add_ip(ioc, "threatfox")
        elif ioc_type in {"domain", "hostname"}:
            buckets.add_domain(ioc, "threatfox")
        elif ioc_type in {"url"}:
            buckets.add_url(ioc, "threatfox")
        elif ioc_type in {"md5_hash", "sha1_hash", "sha256_hash", "hash"}:
            buckets.add_hash(ioc, "threatfox")
        else:
            # best-effort fallback
            if ioc.startswith("http"):
                buckets.add_url(ioc, "threatfox")
            elif IPV4_RE.match(strip_port(ioc)):
                buckets.add_ip(ioc, "threatfox")
            elif SHA256_RE.fullmatch(ioc) or MD5_RE.fullmatch(ioc) or SHA1_RE.fullmatch(ioc):
                buckets.add_hash(ioc, "threatfox")
            elif DOMAIN_RE.fullmatch(ioc.lower().rstrip(".")):
                buckets.add_domain(ioc, "threatfox")

    return {
        "raw_rows": raw,
        "status": "ok" if raw else "empty",
        "ioc_types": dict(types),
    }


def parse_sslbl(path: Path, buckets: Buckets) -> dict:
    text = load_text(path)
    rows = csv_rows_skipping_comments(text)
    raw = 0
    for row in rows:
        if not row:
            continue
        sha1 = row[0].strip().strip('"').lower()
        if SHA1_RE.fullmatch(sha1):
            raw += 1
            buckets.add_ssl(sha1, "sslbl")
    return {"raw_rows": raw, "status": "ok" if raw else "empty"}


def parse_feodo(path: Path, buckets: Buckets) -> dict:
    raw = 0
    for line in load_text(path).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ip = line.split(",")[0].split()[0]
        if IPV4_RE.fullmatch(ip):
            raw += 1
            buckets.add_ip(ip, "feodo")
    status = "empty" if raw == 0 else "ok"
    note = None
    if raw == 0:
        note = "Feodo Tracker often empty after botnet takedowns — treat as empty, not failed"
    return {"raw_rows": raw, "status": status, "note": note}


def parse_ipsum(path: Path, buckets: Buckets, min_score: int) -> dict:
    raw = 0
    kept = 0
    for line in load_text(path).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"[\s,]+", line)
        ip = parts[0]
        score = 1
        if len(parts) > 1 and parts[1].isdigit():
            score = int(parts[1])
        if not IPV4_RE.fullmatch(ip):
            continue
        raw += 1
        if score >= min_score:
            kept += 1
            buckets.add_ip(ip, "ipsum")
    return {
        "raw_rows": raw,
        "kept_rows": kept,
        "min_score": min_score,
        "status": "ok" if raw else "empty",
    }


PARSERS = {
    "urlhaus": parse_urlhaus,
    "threatfox": parse_threatfox,
    "sslbl": parse_sslbl,
    "feodo": parse_feodo,
}


def resolve_feed_file(day_dir: Path, names: list[str]) -> Path | None:
    for name in names:
        candidate = day_dir / name
        if candidate.is_file() and candidate.stat().st_size > 0:
            return candidate
    for name in names:
        candidate = day_dir / name
        if candidate.is_file():
            return candidate
    return None


def write_lines(path: Path, values: set[str]) -> None:
    path.write_text(
        "\n".join(sorted(values)) + ("\n" if values else ""),
        encoding="utf-8",
    )


def write_cdb(path: Path, values: set[str]) -> None:
    """Wazuh CDB list: key:  (empty value)."""
    lines = [f"{v}:" for v in sorted(values)]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize daily IOC dumps")
    parser.add_argument("--output-root", default="Output", help="Output/ root")
    parser.add_argument("--day-dir", default=None, help="Explicit YYYYMMDD folder")
    parser.add_argument("--ipsum-min-score", type=int, default=IPSUM_MIN_SCORE)
    parser.add_argument("--no-cdb", action="store_true", help="Skip Wazuh CDB files")
    args = parser.parse_args()

    output_root = Path(args.output_root)
    day_dir = find_day_dir(output_root, args.day_dir)
    print(f"[*] Normalizing {day_dir}")

    buckets = Buckets()
    feeds_meta = {}

    for feed, names in FEED_FILES.items():
        path = resolve_feed_file(day_dir, names)
        if path is None:
            feeds_meta[feed] = {
                "file": names[0],
                "status": "missing",
                "raw_rows": 0,
            }
            print(f"    - {feed}: MISSING")
            continue

        info = {
            "file": path.name,
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        try:
            if feed == "ipsum":
                parsed = parse_ipsum(path, buckets, args.ipsum_min_score)
            else:
                parsed = PARSERS[feed](path, buckets)
            info.update(parsed)
        except Exception as exc:
            info["status"] = "error"
            info["error"] = str(exc)
            info["raw_rows"] = 0
        feeds_meta[feed] = info
        print(f"    - {feed}: {info.get('status')} raw={info.get('raw_rows', 0)} ({path.name})")

    write_lines(day_dir / "ips.txt", buckets.ips)
    write_lines(day_dir / "domains.txt", buckets.domains)
    write_lines(day_dir / "urls.txt", buckets.urls)
    write_lines(day_dir / "hashes.txt", buckets.hashes)
    write_lines(day_dir / "ssl_sha1.txt", buckets.ssl_sha1)

    if not args.no_cdb:
        cdb_dir = day_dir / "cdb"
        cdb_dir.mkdir(exist_ok=True)
        write_cdb(cdb_dir / "ioc_ips", buckets.ips)
        write_cdb(cdb_dir / "ioc_domains", buckets.domains)
        write_cdb(cdb_dir / "ioc_hashes", buckets.hashes)
        write_cdb(cdb_dir / "ioc_ssl_sha1", buckets.ssl_sha1)

    counts = {
        "ips": len(buckets.ips),
        "domains": len(buckets.domains),
        "urls": len(buckets.urls),
        "hashes": len(buckets.hashes),
        "ssl_sha1": len(buckets.ssl_sha1),
    }

    ok_feeds = sum(1 for m in feeds_meta.values() if m.get("status") == "ok")
    empty_feeds = sum(1 for m in feeds_meta.values() if m.get("status") == "empty")
    missing_feeds = sum(1 for m in feeds_meta.values() if m.get("status") in {"missing", "error"})

    latest = {
        "generated_at": utc_now(),
        "day": day_dir.name,
        "day_path": str(day_dir).replace("\\", "/"),
        "counts": counts,
        "whitelist_dropped": dict(buckets.wl_dropped),
        "source_counts": dict(buckets.source_counts),
        "feeds": feeds_meta,
        "health": {
            "ok": ok_feeds,
            "empty": empty_feeds,
            "missing_or_error": missing_feeds,
            "total_configured": len(FEED_FILES),
        },
        "ipsum_min_score": args.ipsum_min_score,
        "notes": [
            "Lab / personal detection-engineering use. Respect source ToS.",
            "Feodo empty after takedowns is expected.",
            "IPsum filtered by min score to keep Wazuh lists usable.",
        ],
    }

    manifest_path = day_dir / "manifest.json"
    latest_in_day = day_dir / "latest.json"
    manifest_path.write_text(json.dumps(latest, indent=2) + "\n", encoding="utf-8")
    latest_in_day.write_text(json.dumps(latest, indent=2) + "\n", encoding="utf-8")

    root_latest = Path("latest.json")
    root_latest.write_text(json.dumps(latest, indent=2) + "\n", encoding="utf-8")

    site_data = Path("site/data")
    site_data.mkdir(parents=True, exist_ok=True)
    (site_data / "latest.json").write_text(json.dumps(latest, indent=2) + "\n", encoding="utf-8")

    md = [
        f"# Normalized IOCs — {day_dir.name}",
        "",
        f"Generated: `{latest['generated_at']}`",
        "",
        "## Counts (after whitelist + dedup)",
        "",
        f"- IPs: **{counts['ips']}**",
        f"- Domains: **{counts['domains']}**",
        f"- URLs: **{counts['urls']}**",
        f"- Hashes: **{counts['hashes']}**",
        f"- SSL SHA1: **{counts['ssl_sha1']}**",
        "",
        "## Feeds",
        "",
    ]
    for name, meta in feeds_meta.items():
        md.append(
            f"- `{name}`: {meta.get('status')} — raw {meta.get('raw_rows', 0)} — {meta.get('file')}"
        )
        if meta.get("note"):
            md.append(f"  - {meta['note']}")
    md.append("")
    (day_dir / "daily_normalized.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    print()
    print("[+] Counts after whitelist + dedup:")
    for k, v in counts.items():
        print(f"    {k:10} {v}")
    print(f"[+] Wrote {manifest_path}")
    print(f"[+] Wrote {root_latest} and site/data/latest.json")

    # Empty Feodo should not fail the job. Fail only if almost nothing parsed.
    if counts["ips"] + counts["domains"] + counts["urls"] + counts["hashes"] + counts["ssl_sha1"] == 0:
        print("[!] No indicators extracted — check raw files", file=sys.stderr)
        return 1
    if ok_feeds + empty_feeds < 2:
        print("[!] Fewer than 2 usable feeds", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
