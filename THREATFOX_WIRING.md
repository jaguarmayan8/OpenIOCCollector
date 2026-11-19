# ThreatFox wiring — the second feed now reaches the CDB lists

## The gap

ThreatFox was collected every day and used only for hashes. Everything else in
the payload was discarded:

| IOC type | Count (2026-11-19) | Before | After |
| --- | --- | --- | --- |
| `domain` | 4,062 | discarded | **3,588** published |
| `ip:port` | 1,699 | discarded | **1,274** published (port stripped) |
| `url` | 667 | discarded | reduced to host |
| `sha256_hash` | 2,057 | published | published (unchanged) |
| `md5_hash` / `sha1_hash` | 1,001 | published | published (unchanged) |

Worse, URLhaus was the *only* source for the domain list — and URLhaus reports
**payload URLs**, so its domains skew heavily toward distribution platforms. By
contrast ThreatFox reports **the C2 itself**, with a `confidence_level`. That
signal was being collected and thrown away.

## Confidence threshold

ThreatFox confidence distribution on this run:

| Level | IOCs |
| --- | --- |
| 100 | 2,322 |
| 95 | 1,576 |
| 90 | 1,584 |
| 85 | 53 |
| 80 | 193 |
| 75 | 2,761 |
| 70 | 4 |
| 50 | 993 |

Default cut is **75** (`--min-confidence`), keeping 8,489 of 9,486 and dropping
997 — almost all of them at confidence 50, which is where the false-positive
risk concentrates. Raise it to 90 for a tighter, smaller list.

## Result on the 2026-11-19 feed

| List | Before | After |
| --- | --- | --- |
| `malicious-domains.txt` | 767 (URLhaus, filtered) | **4,307** |
| `malicious-ips.txt` | 140,106 (IPsum) | **141,314** |

3,540 domains are net-new — they appear in no URLhaus row. The IP list grows by
1,208 because ThreatFox IPs are **merged into** the IPsum list, not substituted
for it.

Domain IOCs from ThreatFox still pass through the shared-infrastructure filter,
so a `github.com` entry in ThreatFox cannot reintroduce what the domain filter
just removed (20 were suppressed this run).

## Pipeline change

`build_lists.sh` now calls one command instead of two inline heredocs:

```bash
python3 ioc_extract.py lists \
    --urlhaus  "$LATEST_DIR/urlhaus.csv" \
    --threatfox "$LATEST_DIR/threatfox_recent.json" \
    --allow infra_allow.txt \
    --domains-out malicious-domains.txt \
    --ips-out .threatfox-ips.tmp \
    --report "$LATEST_DIR/infra_suppressed.md"
```

ThreatFox IPs land in a sidecar and are unioned with the IPsum output
(`sort -u`), so a missing ThreatFox file degrades to the previous behaviour
instead of emptying the IP list.

## Verifying

```bash
python3 -m unittest discover -s tests -v     # 20 tests
python3 ioc_extract.py lists \
    --urlhaus /tmp/urlhaus.csv \
    --threatfox /tmp/threatfox_recent.json \
    --domains-out /tmp/d.txt --ips-out /tmp/i.txt
grep -c ':80:' /tmp/i.txt       # 0 - ports stripped
head -3 /tmp/d.txt              # CDB format: value:
```

The staleness guard is unaffected: both lists grow, so `MIN_FRACTION=50` passes
without needing an override.

## Not included

`url` IOCs are reduced to their host rather than published as full URLs. A
domain-level CDB rule cannot match a path, so publishing `http://x/y` would add
noise without adding detection. Full-URL matching is a separate list for
web-proxy logs — see `DOMAIN_FILTER.md`.
