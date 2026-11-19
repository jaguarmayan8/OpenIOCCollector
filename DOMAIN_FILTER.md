# Domain filter — why the CDB list no longer contains github.com

## The problem

`malicious-domains.txt` feeds Wazuh rules 100101 / 100102. It was built by
taking the host out of every URLhaus row, but URLhaus reports **payload URLs,
not payload domains**. On 2026-11-19 that meant:

| Host | URLs in the feed |
| --- | --- |
| `github.com` | 53,504 |
| `raw.githubusercontent.com` | 45,243 |
| `cdn.discordapp.com` | 239 |
| `gitlab.com` | 172 |
| `drive.google.com` | 150 |

All seven platform hosts sat in the blocklist, so any rule match fired on
ordinary GitHub fetches, Discord attachments and Drive downloads — including
the tooling that maintains this repository.

## What the filter does

`infra_allow.txt` declares two tiers, and the distinction matters:

- **`platform`** — the registrable domain is shared infrastructure, so the host
  *and all subdomains* are suppressed (`github.com`, `raw.githubusercontent.com`,
  `cdn.discordapp.com`). Specific subdomains are not meaningful threats.
- **`hosting`** — free/consumer platform where each **subdomain is a separate
  tenant**. Only the bare domain is suppressed; `evil.example-host.com` stays
  in the list because that *is* a real indicator. Suppressing subdomains here
  would throw away real detections — and would also block this project's own
  `uberspace`-style github.io page.

Matching is on DNS label boundaries, so `github.com` never matches
`notgithub.com` or `github.com.evil.tld`.

## Numbers from the 2026-11-19 feed

| Metric | Value |
| --- | --- |
| URLhaus rows | 116,572 |
| Rows with a non-IP host | 101,377 |
| Blockable domains published | **767** |
| Suppressed as infrastructure | 99,487 URLs across 62 hosts (**98.1%** of non-IP rows) |
| Infra hosts left in the list | **0** (was 7) |
| Committed list size | 829 -> 767 lines |

Every suppressed host is written to `<day>/infra_suppressed.md` with a sample
URL, so nothing is silently discarded. The full URLs remain in the day's
GitHub Release asset (`iocs-YYYYMMDD`).

## What this does NOT do

It does not detect GitHub-hosted payloads. Blocking the domain is the wrong
control for those; the payload path is (`.../releases/download/v1.0.0/x.zip`).
Options if you want that coverage later: emit a `malicious-urls.txt` CDB list
with full URLs and match it only in web-proxy logs, or alert on the URL fields
of URLhaus rows you care about rather than blocking at the domain level.

## Verifying

```bash
python3 ioc_extract.py check                      # allowlist unit probes
python3 ioc_extract.py check Output/2026/2026-11/20261119/urlhaus.csv   # real split
python3 -m unittest discover -s tests -v          # 15 tests
```
