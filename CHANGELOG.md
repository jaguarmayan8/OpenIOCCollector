# Changelog

Notable changes to OpenIOCCollector. The data itself changes daily and is not
listed here; the dates below are code and pipeline changes.

## 2026-11-25

- **Dashboard has a history.** `docs/history.json` records one point per run
  (published counts, feed health, daily churn) and the page draws a 90-day
  trend with "entered / dropped since the last run". `backfill_history.py`
  reconstructs earlier points from git, so the chart starts populated.
- **Churn is counted on indicators, not lines.** On 2026-11-23 the CDB lists
  gained a provenance tail (`1.0.164.165:` → `1.0.164.165:ipsum`) and a
  line-level diff reported the entire corpus as new. `indicator_key()` now
  mirrors the parser in `lookup.js`.
- **`docs/api/manifest.json`.** Freshness, counts, feed status and per-file
  SHA-256 in one request, for consumers that cannot read a 3 MB text file to
  find out whether it changed.
- **Lookup: cached and with real progress.** The three lists are kept in
  IndexedDB keyed by their data date, so a second visit is instant and a new
  day misses the cache; the first fetch reports bytes received as a
  percentage instead of freezing.
- **Feed card no longer contradicts itself.** "5/6 feeds with data" sat next
  to "all feeds reported data" whenever an empty-but-expected feed (Feodo
  after Operation Endgame) was present. The card now names what is missing
  and draws one segment per feed.
- **Page metadata.** `<meta name="description">`, Open Graph and Twitter card
  tags, a favicon and a generated 1200×630 preview — sharing the link now
  produces a card instead of a bare URL.
- **Mobile layout.** KPI cards are a 2×2 grid under 560 px instead of a
  single tall column.
- **`summary.json` next to `daily_summary.md`.** The collector writes a
  machine-readable twin of its report; the dashboard, the trend and any
  consumer read that instead of regexing Markdown.
- **License is detectable.** `LICENSE` now holds the canonical GPL-3.0 text
  instead of only the notice, which GitHub was classifying as
  `NOASSERTION`/"Other".
- **Container image published to GHCR** on every push to `main` and every
  `v*` tag (`ghcr.io/jaguarmayan8/ioc-collector`).
- **Failed runs close themselves.** The nightly workflow comments on an open
  `[auto] nightly IOC collection failed` issue and closes it once a run
  succeeds, instead of leaving a red issue on the front page.
- `SECURITY.md`, `CONTRIBUTING.md` and this changelog added.

## 2026-11-22

- Raw feed dumps moved to GitHub Release assets; the repository history was
  rewritten to drop ~1 GB of committed dumps (see `SIZE_FIX.md`).

## 2026-11-19

- ThreatFox domains and `ip:port` IOCs are extracted instead of discarded;
  confidence filtering applied to both ThreatFox and URLhaus domains.

## 2026-11-13

- abuse.ch Auth-Key support for URLhaus, ThreatFox and MalwareBazaar
  (keyless export URLs answer `410 Gone`).

## Earlier

- Docker image and one-shot compose job; VirusTotal sample enrichment;
  Wazuh CDB lists with provenance tails; staleness guard; dashboard.
