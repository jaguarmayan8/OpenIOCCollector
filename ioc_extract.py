#!/usr/bin/env python3
"""ioc_extract.py - build CDB lists from a day's raw feed dumps.

Replaces the inline heredocs that used to live in build_lists.sh. Two reasons:

  1. Domain extraction needs a shared-infrastructure filter (infra_allow.txt).
     A domain that IS a platform - github.com, cdn.discordapp.com, pastebin.com -
     is useless and actively harmful as a blocklist entry: it matches the
     platform, not the payload. URLhaus reports payload URLs, so most rows sit
     on shared platforms. Unfiltered, the CDB list blocks the lab's own traffic.

  2. The old parser assumed the URLhaus export had a header row. It does not -
     it is `#` comments followed by data - so the first IOC of every day was
     silently discarded. Header detection here is explicit.

USAGE
    python3 ioc_extract.py domains <urlhaus.csv> <out.txt>
        [--allow infra_allow.txt] [--report <day>/infra_suppressed.txt]

    python3 ioc_extract.py check [urlhaus.csv]
        Validate infra_allow.txt and optionally report the suppression split.
        Writes nothing - run this before editing the allowlist.

OUTPUT
    A CDB list: one `value:` per line, sorted and de-duplicated.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
HOST_RE = re.compile(r"^(?P<host>[^/:?#]+)")
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
IPV6_RE = re.compile(r"^\[?[0-9A-Fa-f:]+\]?$")

PLATFORM = "platform"
HOSTING = "hosting"


class InfraRules:
    """Two tiers of suppression - see infra_allow.txt for why they differ."""

    __slots__ = ("platform", "hosting", "source")

    def __init__(self, platform, hosting, source=""):
        self.platform = set(platform)
        self.hosting = set(hosting)
        self.source = source

    @classmethod
    def load(cls, path):
        platform, hosting = set(), set()
        with open(path, encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, 1):
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split(None, 1)
                if len(parts) != 2:
                    raise ValueError(
                        "%s:%d: expected '<platform|hosting> <domain>', got %r"
                        % (path, lineno, raw.rstrip())
                    )
                tier, domain = parts[0].lower(), parts[1].strip().lower().rstrip(".")
                if tier not in (PLATFORM, HOSTING):
                    raise ValueError("%s:%d: unknown tier %r" % (path, lineno, tier))
                if "." not in domain:
                    raise ValueError("%s:%d: %r is not a domain" % (path, lineno, domain))
                (platform if tier == PLATFORM else hosting).add(domain)
        return cls(platform, hosting, str(path))

    def classify(self, host):
        """Return (reason, matched_entry); reason None means blockable."""
        h = (host or "").strip().lower().rstrip(".")
        if not h or "." not in h or h.startswith("-"):
            return None, None
        if IPV4_RE.match(h) or (":" in h and IPV6_RE.match(h)):
            return None, None  # IPs belong to the IP list, not this filter

        labels = h.split(".")
        # Walk suffixes on label boundaries: a.b.github.com -> b.github.com ->
        # github.com. So `notgithub.com` and `github.com.evil.tld` never match.
        for i in range(0, len(labels) - 1):
            candidate = ".".join(labels[i:])
            if candidate in self.platform:
                return PLATFORM, candidate
            if candidate in self.hosting and candidate == h:
                return "hosting-apex", candidate
        return None, None

    def __len__(self):
        return len(self.platform) + len(self.hosting)


def extract_host(url):
    """Host from a URL or bare hostname: lowercased, no port, no path."""
    text = (url or "").strip()
    if not text:
        return None
    # Strip the scheme explicitly: with an optional scheme group, "http://"
    # backtracks and yields "http" as the host.
    text = SCHEME_RE.sub("", text, count=1)
    m = HOST_RE.match(text)
    if not m:
        return None
    host = m.group("host").strip().rstrip(".").lower()
    if not host or host.startswith(".") or host.startswith("-"):
        return None
    return host


def iter_rows(path):
    """CSV data rows, skipping '#' comments and blank lines."""
    with open(path, newline="", errors="ignore", encoding="utf-8") as fh:
        reader = csv.reader(
            line for line in fh if line.strip() and not line.startswith("#")
        )
        for row in reader:
            yield row


def read_urlhaus(path, url_index=None, sample_limit=10):
    """Split URLhaus hosts into blockable vs suppressed.

    Returns a dict: domains(set), suppressed(Counter), reasons(dict),
    samples(dict), total(int rows with a host), had_header(bool).
    """
    rows = list(iter_rows(path))
    out = {
        "domains": set(),
        "suppressed": Counter(),
        "reasons": {},
        "samples": defaultdict(list),
        "total": 0,
        "had_header": False,
    }
    if not rows:
        return out

    header = [c.strip().lower() for c in rows[0]]
    if "url" in header:
        idx, body, out["had_header"] = header.index("url"), rows[1:], True
    else:
        idx, body = 2, rows
    if url_index is not None:
        idx = url_index

    kept, suppressed = out["domains"], out["suppressed"]
    for row in body:
        if len(row) <= idx:
            continue
        url = row[idx].strip()
        if not url:
            continue
        host = extract_host(url)
        if not host:
            continue
        if IPV4_RE.match(host) or (":" in host and IPV6_RE.match(host)):
            continue  # IP literals belong to the IP list, not the domain list
        out["total"] += 1
        reason, entry = RULES_HOLDER["rules"].classify(host)
        if reason is None:
            kept.add(host)
            continue
        suppressed[host] += 1
        out["reasons"][host] = "%s:%s" % (reason, entry)
        if len(out["samples"][host]) < sample_limit:
            out["samples"][host].append(url)
    return out


# Set by the CLI entry point so read_urlhaus() keeps a simple signature.
RULES_HOLDER = {"rules": InfraRules(set(), set())}


class Provenance:
    """Collects one entry per indicator, with every feed that reported it.

    A CDB file allows one line per key, so an indicator seen by two feeds must
    be MERGED, not appended - two `1.2.3.4:` lines would be duplicate keys and
    Wazuh would keep whichever it parsed last. The value carries the
    provenance: `1.2.3.4:threatfox:100` or, for multiple feeds,
    `1.2.3.4:threatfox:100|ipsum` (highest confidence first).

    Wazuh matches on the KEY only (`match_key` / `address_match_key`), so
    adding a value cannot change which traffic the rules catch. It makes the
    published list self-describing and gives the dashboard's lookup something
    to show besides "found".
    """

    __slots__ = ("_m",)

    def __init__(self, seed=None):
        self._m = {}
        if seed:
            for key, tag in seed.items():
                self.add_tagged(key, tag)

    def add(self, value, source, confidence=None):
        self.add_tagged(
            value,
            "%s:%d" % (source, int(confidence))
            if source and confidence not in (None, "")
            else (source or ""),
        )

    def add_tagged(self, value, tag):
        """Merge a `source:confidence` tag. One level per source, highest wins,
        so a re-run upgrades instead of appending `threatfox:50|threatfox:100`."""
        value = (value or "").strip()
        if not value:
            return
        bucket = self._m.setdefault(value, {})
        for part in (tag or "").split("|"):
            part = part.strip()
            if not part:
                continue
            head, sep, tail = part.rpartition(":")
            if sep and tail.isdigit():
                src, conf = head, int(tail)
            else:
                src, conf = part, None
            prev = bucket.get(src)
            if prev is None or (conf is not None and conf > prev):
                bucket[src] = conf

    def get(self, value):
        bucket = self._m.get(value)
        if not bucket:
            return ""
        order = sorted(bucket, key=lambda k: (-(bucket[k] if bucket[k] is not None else -1), k))
        return "|".join(
            "%s:%d" % (src, bucket[src]) if bucket[src] is not None else src for src in order
        )

    def keys(self):
        return set(self._m)

    def lines(self):
        out = []
        for value in sorted(self._m):
            tag = self.get(value)
            out.append("%s:%s" % (value, tag) if tag else value + ":")
        return out

    def __len__(self):
        return len(self._m)


def parse_tagged(line):
    """Split a list line into (value, tag).

    `1.2.3.4:` -> ("1.2.3.4", ""); `1.2.3.4:threatfox:100` -> ("1.2.3.4",
    "threatfox:100"). A bare value with no colon is returned unchanged - some
    test fixtures write one, and older list versions may too.
    """
    line = (line or "").strip()
    if not line or line.startswith("#"):
        return None, None
    if line.endswith(":"):
        return line[:-1], ""
    head, sep, tail = line.partition(":")
    if not sep:
        return line, ""
    if ":" in head:  # an IPv6 key with no terminator - keep it whole
        return line, ""
    return head, tail


def read_tagged_file(path):
    """Merged Provenance from an existing tagged list (missing file -> empty)."""
    prov = Provenance()
    path = Path(path)
    if not path.exists():
        return prov
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        value, tag = parse_tagged(line)
        if value:
            prov.add_tagged(value, tag)
    return prov


def write_cdb_lines(lines, path, preserve_on_empty=False):
    """Write pre-formatted CDB lines, sorted, never truncating on empty."""
    ordered = sorted(set(lines))
    if not ordered and preserve_on_empty and Path(path).exists():
        kept = sum(
            1
            for l in Path(path).read_text(encoding="utf-8").splitlines()
            if l.strip()
        )
        if kept:
            print(
                "[!] %s: no entries this run - KEEPING previous %d-entry file"
                % (path, kept)
            )
            return kept
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for v in ordered:
            fh.write(v + "\n")
    return len(ordered)


def write_cdb(values, path, preserve_on_empty=False):
    """Write a CDB list of bare values. With preserve_on_empty, an empty result
    never truncates an existing non-empty file - the previous list is kept and
    the caller is told, because "" published to Wazuh blinds the rules."""
    ordered = sorted(set(values))
    if not ordered and preserve_on_empty and Path(path).exists():
        kept = sum(1 for l in Path(path).read_text(encoding="utf-8").splitlines() if l.strip())
        if kept:
            print("[!] %s: no entries this run - KEEPING previous %d-entry file"
                  % (path, kept))
            return kept
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for v in ordered:
            fh.write(v + ":\n")
    return len(ordered)


def write_report(path, result):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    suppressed = result["suppressed"]
    total = result["total"]
    n_urls = sum(suppressed.values())
    pct = (100.0 * n_urls / total) if total else 0.0
    lines = [
        "# Shared-infrastructure domains suppressed from the CDB list",
        "",
        "%d URL(s) across %d host(s) - %.1f%% of %d rows with a host."
        % (n_urls, len(suppressed), pct, total),
        "",
        "These are platform domains, not payload domains. Blocking them would",
        "match the platform instead of the malware. The full URLs are preserved",
        "in the day's release asset (`iocs-<date>`).",
        "",
        "| Host | URLs | Matched rule | Sample URL |",
        "| --- | --- | --- | --- |",
    ]
    for host, count in suppressed.most_common(50):
        sample = (result["samples"].get(host) or [""])[0]
        lines.append(
            "| `%s` | %d | `%s` | %s |"
            % (host, count, result["reasons"].get(host, ""), sample)
        )
    if len(suppressed) > 50:
        lines.append("\n_...and %d more hosts._" % (len(suppressed) - 50))
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def cmd_domains(args):
    rules = InfraRules.load(args.allow)
    RULES_HOLDER["rules"] = rules
    result = read_urlhaus(args.urlhaus)
    n = write_cdb(result["domains"], args.out)
    supp = result["suppressed"]
    total = result["total"]
    print("URLhaus rows with a host: %d (header: %s)" % (total, result["had_header"]))
    print("Blockable domains:        %d" % n)
    print(
        "Suppressed (infra):       %d URLs / %d hosts (%.1f%%)"
        % (sum(supp.values()), len(supp), (100.0 * sum(supp.values()) / total) if total else 0.0)
    )
    if args.report:
        write_report(args.report, result)
        print("Report:                   %s" % args.report)
    return 0


def cmd_check(args):
    rules = InfraRules.load(args.allow)
    print(
        "infra_allow.txt: %d platform + %d hosting = %d entries"
        % (len(rules.platform), len(rules.hosting), len(rules))
    )
    probes = [
        "github.com", "raw.githubusercontent.com", "cdn.discordapp.com",
        "pastebin.com", "notgithub.com", "github.com.evil.tld",
        "000webhostapp.com", "evil.000webhostapp.com",
        "github.io", "jaguarmayan8.github.io", "example.org",
    ]
    for probe in probes:
        reason, entry = rules.classify(probe)
        label = ("%s (%s)" % (reason, entry)) if reason else "BLOCKABLE"
        print("  %-32s -> %s" % (probe, reason or "BLOCKABLE"))
        _ = entry
    if args.urlhaus:
        RULES_HOLDER["rules"] = rules
        result = read_urlhaus(args.urlhaus)
        supp = result["suppressed"]
        print("\n%-34s %8s  %s" % ("HOST", "URLS", "MATCHED"))
        for host, count in supp.most_common(15):
            print("%-34s %8d  %s" % (host, count, result["reasons"][host]))
        print(
            "\ntotal rows %d | blockable %d | suppressed %d URLs / %d hosts"
            % (
                result["total"], len(result["domains"]),
                sum(supp.values()), len(supp),
            )
        )
    return 0



# ---------------------------------------------------------------------------
# ThreatFox
# ---------------------------------------------------------------------------

IPV4_PORT_RE = re.compile(r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<port>\d{1,5}))?$")


def read_threatfox(path, min_confidence=75, rules=None):
    """Extract domains and IPs from a ThreatFox get_iocs payload.

    Returns a dict: domains(set), ips(set), stats(Counter), skipped(Counter).

    ThreatFox labels every IOC with a confidence_level. The default cut is 75:
    on 2026-11-19 that keeps 8,489 of 9,486 IOCs and discards 997 low-confidence
    entries (993 at 50, 4 at 70), which is where the false-positive risk sits.

    `ip:port` is split - the port is not part of a CDB IP entry, and a port is
    not an indicator on its own for these rule sets.
    """
    rules = rules or InfraRules(set(), set())
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    iocs = data.get("iocs") if isinstance(data, dict) else data
    if not isinstance(iocs, list):
        iocs = []

    # value -> highest confidence seen for it. Dicts, not sets: the confidence
    # level is the single most useful signal ThreatFox carries, and it used to
    # be discarded right after the >=75 filter that consumed it.
    domains, ips = {}, {}
    stats, skipped = Counter(), Counter()
    n_iocs = 0

    def note(bucket, key, conf):
        if conf > bucket.get(key, -1):
            bucket[key] = conf

    for item in iocs:
        if not isinstance(item, dict):
            continue
        ioc_type = (item.get("ioc_type") or "").lower()
        value = (item.get("ioc") or item.get("ioc_value") or "").strip().lower()
        if not value:
            skipped["empty"] += 1
            continue
        n_iocs += 1
        conf = item.get("confidence_level")
        try:
            conf = int(conf) if conf is not None else 0
        except (TypeError, ValueError):
            conf = 0
        if conf < min_confidence:
            skipped["low_confidence"] += 1
            continue

        if ioc_type == "domain":
            reason, _entry = rules.classify(value)
            if reason:
                skipped["infra:" + reason] += 1
                continue
            note(domains, value, conf)
            stats["domain"] += 1
        elif ioc_type in ("ip:port", "ip"):
            m = IPV4_PORT_RE.match(value)
            if not m:
                skipped["unparsable_ip"] += 1
                continue
            note(ips, m.group("ip"), conf)
            stats["ip"] += 1
        elif ioc_type == "url":
            host = extract_host(value)
            if not host:
                skipped["unparsable_url"] += 1
                continue
            if IPV4_RE.match(host):
                note(ips, host, conf)
                stats["url->ip"] += 1
            else:
                reason, _entry = rules.classify(host)
                if reason:
                    skipped["infra:" + reason] += 1
                    continue
                note(domains, host, conf)
                stats["url->domain"] += 1
        else:
            skipped[ioc_type or "unknown"] += 1

    return {"domains": domains, "ips": ips, "stats": stats,
            "skipped": skipped, "n_iocs": n_iocs}


def cmd_lists(args):
    """Full build: URLhaus + ThreatFox -> domain and IP CDB lists."""
    rules = InfraRules.load(args.allow)

    RULES_HOLDER["rules"] = rules
    uh = read_urlhaus(args.urlhaus) if args.urlhaus else None
    tf = (
        read_threatfox(args.threatfox, min_confidence=args.min_confidence, rules=rules)
        if args.threatfox
        else {"domains": {}, "ips": {}, "stats": Counter(),
              "skipped": Counter(), "n_iocs": 0}
    )

    urlhaus_domains = uh["domains"] if uh else set()
    tf_domains = tf["domains"]

    # Provenance, not just values: a domain carried by both feeds becomes ONE
    # line listing both, so the value can never create a duplicate CDB key.
    all_domains = Provenance()
    for domain in urlhaus_domains:
        all_domains.add(domain, "urlhaus")
    for domain, conf in tf_domains.items():
        all_domains.add(domain, "threatfox", conf)

    # IPs: the ipsum feed is already handled by the collector as
    # top_malicious.txt. ThreatFox only contributes IPs it observed as C2,
    # which is a different and more specific signal.
    all_ips = Provenance()
    for ip, conf in tf["ips"].items():
        all_ips.add(ip, "threatfox", conf)

    n_dom = write_cdb_lines(all_domains.lines(), args.domains_out, preserve_on_empty=True)
    n_ip = write_cdb_lines(all_ips.lines(), args.ips_out, preserve_on_empty=True)

    # ThreatFox-only domains, committed so a later day whose ThreatFox call
    # returns nothing can carry this component forward instead of dropping
    # ~2,900 domains out of the union and tripping the guard.
    tf_out = getattr(args, "tf_domains_out", None)
    if tf_out and tf_domains:
        # Only when non-empty: a 0-byte sidecar makes the next run's
        # `[ -s file ]` test false and silently disables carry-forward.
        # Tagged like the main list, so a carried-forward component keeps its
        # provenance instead of being demoted to a bare value.
        side = Provenance()
        for domain, conf in tf_domains.items():
            side.add(domain, "threatfox", conf)
        write_cdb_lines(side.lines(), tf_out)

    print("URLhaus domains (filtered):  %d" % len(urlhaus_domains))
    print("ThreatFox domains (conf>=%d): %d" % (args.min_confidence, len(tf_domains)))
    print("  new from ThreatFox only:   %d" % len(set(tf_domains) - urlhaus_domains))
    print("Domain list written:         %d" % n_dom)
    print("SUMMARY " + json.dumps({
        "urlhaus_rows": uh["total"] if uh else 0,
        "urlhaus_domains": len(urlhaus_domains),
        "threatfox_iocs": tf.get("n_iocs", 0),
        "threatfox_domains": len(tf_domains),
        "threatfox_ips": len(tf["ips"]),
    }, sort_keys=True))
    print("ThreatFox IPs (conf>=%d):     %d" % (args.min_confidence, n_ip))
    print("IP list written:             %d" % n_ip)

    tf_skipped = tf["skipped"]
    if tf_skipped:
        print("ThreatFox skipped:           " + ", ".join(
            "%s=%d" % (k, v) for k, v in tf_skipped.most_common()
        ))

    if args.report and uh is not None:
        write_report(args.report, uh)
        print("Report:                      %s" % args.report)
    return 0


def count_threatfox_iocs(path):
    """Usable IOC entries in a ThreatFox payload; 0 for missing/empty/broken.

    A collector that failed still writes {"iocs": []} (17 bytes), so a
    file-size test cannot tell "feed is quiet" from "the feed never loaded".
    """
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return 0
    iocs = data.get("iocs") if isinstance(data, dict) else data
    return len([i for i in iocs if isinstance(i, dict) and (i.get("ioc") or i.get("ioc_value"))]) if isinstance(iocs, list) else 0


def read_ipsum(path):
    """IPs from the IPsum aggregate - first token of each non-comment line.

    IPsum's aggregate file carries no confidence level, so the tag is the bare
    source name: the lookup shows "ipsum" with no number rather than inventing
    one.
    """
    prov = Provenance()
    for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split()[0]
        if IPV4_RE.match(token):
            prov.add(token, "ipsum")
    return prov


def cmd_ips(args):
    """IPsum + ThreatFox -> one tagged IP list, merged by key."""
    prov = read_ipsum(args.ipsum) if args.ipsum else Provenance()
    n_ipsum, n_tf = len(prov), 0
    if args.threatfox:
        rules = (
            InfraRules.load(args.allow)
            if args.allow and Path(args.allow).exists()
            else InfraRules(set(), set())
        )
        tf = read_threatfox(args.threatfox, min_confidence=args.min_confidence, rules=rules)
        for ip, conf in tf["ips"].items():
            prov.add(ip, "threatfox", conf)
        n_tf = len(tf["ips"])
    n = write_cdb_lines(prov.lines(), args.out, preserve_on_empty=True)
    print("ipsum IPs:                   %d" % n_ipsum)
    print("ThreatFox C2 IPs:            %d" % n_tf)
    print("IP list written:             %d" % n)
    return 0


def cmd_merge(args):
    """Union tagged list files BY KEY, merging their provenance.

    `sort -u fileA fileB` keeps `1.2.3.4:` and `1.2.3.4:threatfox:100` as two
    lines with the same CDB key - a duplicate key in the database, not a richer
    entry.
    """
    prov = Provenance()
    for path in args.inputs:
        if not Path(path).exists():
            continue
        other = read_tagged_file(path)
        for key in other.keys():
            prov.add_tagged(key, other.get(key))
    n = write_cdb_lines(prov.lines(), args.out, preserve_on_empty=True)
    print("merge: %d unique keys -> %s" % (n, args.out))
    return 0


def cmd_hashes(args):
    """ThreatFox hashes -> CDB list, never truncating a good previous file."""
    n_iocs = count_threatfox_iocs(args.threatfox)
    if not n_iocs:
        kept = write_cdb(set(), args.out, preserve_on_empty=True)
        print("ThreatFox payload has 0 usable IOCs - previous %d-entry hash list kept" % kept)
        return 0
    hashes = Provenance()
    with open(args.threatfox, encoding="utf-8") as fh:
        data = json.load(fh)
    entries = data.get("iocs") if isinstance(data, dict) else data
    for item in entries or []:
        if not isinstance(item, dict):
            continue
        ioc_type = (item.get("ioc_type") or "").lower()
        value = (item.get("ioc") or item.get("ioc_value") or "").lower().strip()
        try:
            conf = int(item.get("confidence_level"))
        except (TypeError, ValueError):
            conf = None
        if ioc_type in ("md5_hash", "sha1_hash", "sha256_hash") and value:
            hashes.add(value, "threatfox", conf)
        for sample in item.get("malware_samples") or []:
            for k in ("md5_hash", "sha1_hash", "sha256_hash"):
                if sample.get(k):
                    hashes.add(sample[k].lower(), "threatfox", conf)
    n = write_cdb_lines(hashes.lines(), args.out, preserve_on_empty=True)
    print("ThreatFox IOCs: %d -> %d hashes written" % (n_iocs, n))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="Build CDB lists from raw IOC dumps")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("domains", help="URLhaus CSV -> domain CDB list")
    d.add_argument("urlhaus")
    d.add_argument("out")
    d.add_argument("--allow", default="infra_allow.txt")
    d.add_argument("--report", default=None)
    d.set_defaults(func=cmd_domains)

    l = sub.add_parser("lists", help="URLhaus + ThreatFox -> domain and IP CDB lists")
    l.add_argument("--urlhaus", default=None)
    l.add_argument("--threatfox", default=None)
    l.add_argument("--allow", default="infra_allow.txt")
    l.add_argument("--domains-out", default="malicious-domains.txt")
    l.add_argument("--ips-out", default="malicious-ips.txt")
    l.add_argument("--min-confidence", type=int, default=75)
    l.add_argument("--report", default=None)
    l.add_argument("--tf-domains-out", default=None,
                   help="sidecar of ThreatFox-only domains (carry-forward source)")
    l.set_defaults(func=cmd_lists)

    i = sub.add_parser("ips", help="IPsum + ThreatFox -> tagged IP CDB list")
    i.add_argument("--ipsum", default=None)
    i.add_argument("--threatfox", default=None)
    i.add_argument("--allow", default=None)
    i.add_argument("--out", default="malicious-ips.txt")
    i.add_argument("--min-confidence", type=int, default=75)
    i.set_defaults(func=cmd_ips)

    m = sub.add_parser("merge", help="union tagged list files by key")
    m.add_argument("--out", required=True)
    m.add_argument("inputs", nargs="+")
    m.set_defaults(func=cmd_merge)

    n = sub.add_parser("count", help="print usable IOC count for a payload")
    n.add_argument("--threatfox", required=True)
    n.set_defaults(func=cmd_count)

    h = sub.add_parser("hashes", help="ThreatFox JSON -> hash CDB list")
    h.add_argument("threatfox")
    h.add_argument("out")
    h.set_defaults(func=cmd_hashes)

    c = sub.add_parser("check", help="validate allowlist, optionally against a CSV")
    c.add_argument("urlhaus", nargs="?", default=None)
    c.add_argument("--allow", default="infra_allow.txt")
    c.set_defaults(func=cmd_check)

    args = p.parse_args(argv)
    return args.func(args)


def cmd_count(args):
    print(count_threatfox_iocs(args.threatfox))
    return 0



if __name__ == "__main__":
    raise SystemExit(main())
