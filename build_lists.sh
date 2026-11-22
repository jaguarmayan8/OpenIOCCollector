#!/bin/bash
# Shared post-collection pipeline: CDB list extraction, staleness guard,
# VirusTotal enrichment, dashboard generation, retention pruning and SHA256
# checksums for the Wazuh puller.
#
# This is the ONLY copy of the pipeline logic. run_and_push.sh (Kali cron) and
# .github/workflows/collector.yml (GitHub Actions) both call it - the previous
# duplicated copy in run_and_push.sh had already drifted (no checksums step,
# hardcoded paths) and would have re-written the .prev files that are no
# longer tracked.
set -euo pipefail
cd "$(dirname "$0")"

# Byte order for every sort/compare below, regardless of the host's locale.
# A CI runner, a Kali cron job and a Mac all collate "1.2.3.4:" differently
# once punctuation is ignored, so identical data could serialise to different
# bytes - and a byte-different list is a whole-file diff.
export LC_ALL=C

echo "=== Finding latest output directory ==="
LATEST_DIR=$(find Output -type d -name "$(date +%Y%m%d)" | sort | tail -1)

if [ -z "$LATEST_DIR" ]; then
  echo "ERROR: Could not find today's output directory"
  exit 1
fi

echo "Using directory: $LATEST_DIR"

echo "=== Building CDB lists ==="
# A missing/empty feed file must NOT abort the whole build: the collector
# tolerates partial failures on purpose, and the staleness guard below will
# refuse to push a list that shrank or went empty. So: if a feed file is
# missing, skip that extraction and KEEP THE PREVIOUS LIST (it is in the
# working tree from the last commit) - the guard then sees an unchanged
# count and passes it through.

# IPs from IPsum (the aggregated multi-source blocklist).
if [ -s "$LATEST_DIR/top_malicious.txt" ]; then
  grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$LATEST_DIR/top_malicious.txt" | awk '{print $1":"}' > malicious-ips.txt
else
  echo "[!] top_malicious.txt missing/empty - keeping previous malicious-ips.txt"
fi

# Domains from URLhaus (infra-filtered) PLUS ThreatFox, and C2 IPs from
# ThreatFox. ThreatFox was previously used only for hashes, so its 4,062
# domains and 1,699 ip:port entries were collected daily and thrown away -
# despite carrying a confidence_level that URLhaus does not.
# ThreatFox IPs are written to a sidecar and merged below so they are added to
# the ipsum list rather than replacing it.
# A 17-byte {"iocs": []} is written even when the API call failed, so `-s`
# (file is non-empty) cannot tell "quiet feed" from "never loaded". Ask for the
# number of USABLE IOCs; zero is then treated exactly like a missing file.
TF_IOCS=$(python3 ioc_extract.py count --threatfox "$LATEST_DIR/threatfox_recent.json" 2>/dev/null || echo 0)
[ -z "$TF_IOCS" ] && TF_IOCS=0
if [ "$TF_IOCS" -eq 0 ] && [ -f "$LATEST_DIR/threatfox_recent.json" ]; then
  echo "[!] ThreatFox payload holds 0 usable IOCs - treating it as missing"
fi

if [ -s "$LATEST_DIR/urlhaus.csv" ] || [ "$TF_IOCS" -gt 0 ]; then
  UH=""
  TF=""
  [ -s "$LATEST_DIR/urlhaus.csv" ] && UH="$LATEST_DIR/urlhaus.csv"
  [ "$TF_IOCS" -gt 0 ] && TF="$LATEST_DIR/threatfox_recent.json"
  python3 ioc_extract.py lists \
      ${UH:+--urlhaus "$UH"} \
      ${TF:+--threatfox "$TF"} \
      --allow infra_allow.txt \
      --domains-out malicious-domains.txt \
      --ips-out .threatfox-ips.tmp \
      --tf-domains-out threatfox-domains.txt \
      --report "$LATEST_DIR/infra_suppressed.md"

  # ThreatFox contributed nothing: re-add yesterday's ThreatFox domains so the
  # union does not lose ~2,900 entries and trip the guard. The sidecar is
  # committed, so this survives an outage instead of blocking the publish.
  if [ "$TF_IOCS" -eq 0 ] && [ -s threatfox-domains.txt ]; then
    sort -u malicious-domains.txt threatfox-domains.txt -o malicious-domains.txt
    echo "[!] STALE COMPONENT: carried forward $(wc -l < threatfox-domains.txt) previous ThreatFox domains"
  fi

  if [ -s .threatfox-ips.tmp ]; then
    # Union with the ipsum list, keep it sorted and deduplicated.
    sort -u malicious-ips.txt .threatfox-ips.tmp > .ips.merged
    mv .ips.merged malicious-ips.txt
    echo "[+] merged $(wc -l < .threatfox-ips.tmp) ThreatFox C2 IPs into malicious-ips.txt"
    rm -f .threatfox-ips.tmp
  fi
else
  echo "[!] no URLhaus/ThreatFox data - keeping previous lists"
fi

# Hashes from ThreatFox (new API: value field is "ioc"; old export was
# "ioc_value"; also pulls hashes attached via malware_samples)
if [ "$TF_IOCS" -gt 0 ]; then
  python3 ioc_extract.py hashes "$LATEST_DIR/threatfox_recent.json" malicious-hashes.txt
else
  # Hashes come only from ThreatFox, so a zero-IOC payload would empty the
  # list. Never write it - the previous file is the last known good.
  echo "[!] STALE COMPONENT: keeping previous malicious-hashes.txt ($(wc -l < malicious-hashes.txt) entries)"
fi

echo "=== Normalising lists (byte order, deduplicated) ==="
# The published files are sorted here, once, so that identical input always
# produces identical bytes: the same list from either producer gives the same
# file, and a day's commit shows only the entries that actually changed
# instead of rewriting the file because the feed listed them in another order.
# The IP list in particular arrives in IPsum's own order (unsorted) and is only
# sorted today when a ThreatFox merge happens to run.
for f in malicious-ips.txt malicious-domains.txt malicious-hashes.txt; do
  [ -s "$f" ] || continue
  before=$(wc -l < "$f")
  sort -u "$f" -o "$f"
  after=$(wc -l < "$f")
  if [ "$before" -ne "$after" ]; then
    echo "  $f: $before -> $after lines ($((before - after)) duplicates dropped)"
  fi
done

echo "IPs: $(wc -l < malicious-ips.txt)"
echo "Domains: $(wc -l < malicious-domains.txt)"
echo "Hashes: $(wc -l < malicious-hashes.txt)"

echo "=== Sanity check before pushing ==="
# A list that is EMPTY, or collapsed to a tiny fraction of its previous size,
# almost always means an upstream feed broke (410, auth expired, format
# change) - not that the internet got safer. Pushing that to Wazuh would
# silently blind rules 100100-100111.
#
# The previous size is read from the last COMMIT (git show HEAD:<file>) rather
# than from a committed .prev snapshot. Git history already stores every
# version, so the .prev files were a second copy of the same data in the tree
# - 2.2 MB on disk plus a duplicate ~2 MB blob in history every single day.
MIN_FRACTION=50   # block push if new list < MIN_FRACTION% of previous
MIN_ABSOLUTE=10   # ... or if it has fewer entries than this

prev_count() {
  local file="$1" n=""
  if git cat-file -e "HEAD:$file" 2>/dev/null; then
    n=$(git show "HEAD:$file" | wc -l || true)
    echo "${n:-0}"
  elif [ -f "$file.prev" ]; then
    # Fallback for a repo whose HEAD does not have the file yet (first run).
    wc -l < "$file.prev"
  else
    echo 0
  fi
}

check_list() {
  local name="$1" file="$2" count prev_count_val
  if [ ! -f "$file" ]; then
    echo "ABORT: $file missing"
    exit 1
  fi
  count=$(wc -l < "$file")
  if [ "$count" -lt "$MIN_ABSOLUTE" ]; then
    echo "ABORT: $file has only $count entries (< $MIN_ABSOLUTE) - upstream feed likely broken"
    exit 1
  fi
  prev_count_val=$(prev_count "$file")
  # only compare when the previous list was itself non-trivial
  if [ "${prev_count_val:-0}" -ge "$MIN_ABSOLUTE" ]; then
    if [ $(( count * 100 / prev_count_val )) -lt "$MIN_FRACTION" ]; then
      echo "ABORT: $file collapsed from $prev_count_val to $count entries (< ${MIN_FRACTION}% of previous) - refusing to push"
      # 75 = deliberately blocked, NOT a crash: the workflow reports these as
      # two different kinds of issue, because "upstream feed was thin today"
      # needs no code debugging and should not page anyone at 03:00.
      exit 75
    fi
  fi
  echo "OK: $name ($count entries, previous $prev_count_val)"
}

check_list "malicious-ips"      malicious-ips.txt
check_list "malicious-domains"  malicious-domains.txt
check_list "malicious-hashes"   malicious-hashes.txt

echo "=== VirusTotal enrichment ==="
python3 vt_enrich.py

echo "=== Generate dashboard ==="
python3 generate_dashboard.py

echo "=== Pruning old output (two-tier retention) ==="
# raw dumps (urlhaus.csv ~30 MB/day, threatfox ~7 MB/day) are disposable -
# they are published as GitHub Release assets by publish_raw.sh. Summaries and
# VT results are tiny and kept as history.
#   RAW_KEEP_DAYS=3 DERIVED_DAYS=90 by default
# Runs BEFORE the commit so deletions are pushed with today's update.
python3 prune_output.py

echo "=== Generating checksums (for the Wazuh puller) ==="
# The manager-side wazuh_pull_lists.sh verifies these before installing -
# anything modified between GitHub and the manager is rejected.
sha256sum malicious-ips.txt malicious-domains.txt malicious-hashes.txt > checksums.sha256
cat checksums.sha256

echo "=== Build stage done ==="
