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


def write_cdb(values, path):
    ordered = sorted(set(values))
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
    data = json.loads(open(path, encoding="utf-8").read())
    iocs = data.get("iocs") if isinstance(data, dict) else data
    if not isinstance(iocs, list):
        iocs = []

    domains, ips = set(), set()
    stats, skipped = Counter(), Counter()

    for item in iocs:
        if not isinstance(item, dict):
            continue
        ioc_type = (item.get("ioc_type") or "").lower()
        value = (item.get("ioc") or item.get("ioc_value") or "").strip().lower()
        if not value:
            skipped["empty"] += 1
            continue
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
            domains.add(value)
            stats["domain"] += 1
        elif ioc_type in ("ip:port", "ip"):
            m = IPV4_PORT_RE.match(value)
            if not m:
                skipped["unparsable_ip"] += 1
                continue
            ips.add(m.group("ip"))
            stats["ip"] += 1
        elif ioc_type == "url":
            host = extract_host(value)
            if not host:
                skipped["unparsable_url"] += 1
                continue
            if IPV4_RE.match(host):
                ips.add(host)
                stats["url->ip"] += 1
            else:
                reason, _entry = rules.classify(host)
                if reason:
                    skipped["infra:" + reason] += 1
                    continue
                domains.add(host)
                stats["url->domain"] += 1
        else:
            skipped[ioc_type or "unknown"] += 1

    return {"domains": domains, "ips": ips, "stats": stats, "skipped": skipped}


def cmd_lists(args):
    """Full build: URLhaus + ThreatFox -> domain and IP CDB lists."""
    rules = InfraRules.load(args.allow)

    RULES_HOLDER["rules"] = rules
    uh = read_urlhaus(args.urlhaus) if args.urlhaus else None
    tf = (
        read_threatfox(args.threatfox, min_confidence=args.min_confidence, rules=rules)
        if args.threatfox
        else {"domains": set(), "ips": set(), "stats": Counter(), "skipped": Counter()}
    )

    urlhaus_domains = uh["domains"] if uh else set()
    tf_domains = tf["domains"]
    all_domains = urlhaus_domains | tf_domains

    # IPs: the ipsum feed is already handled by the collector as
    # top_malicious.txt. ThreatFox only contributes IPs it observed as C2,
    # which is a different and more specific signal.
    all_ips = set(tf["ips"])

    n_dom = write_cdb(all_domains, args.domains_out)
    n_ip = write_cdb(all_ips, args.ips_out)

    print("URLhaus domains (filtered):  %d" % len(urlhaus_domains))
    print("ThreatFox domains (conf>=%d): %d" % (args.min_confidence, len(tf_domains)))
    print("  new from ThreatFox only:   %d" % len(tf_domains - urlhaus_domains))
    print("Domain list written:         %d" % n_dom)
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
    l.set_defaults(func=cmd_lists)

    c = sub.add_parser("check", help="validate allowlist, optionally against a CSV")
    c.add_argument("urlhaus", nargs="?", default=None)
    c.add_argument("--allow", default="infra_allow.txt")
    c.set_defaults(func=cmd_check)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
