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

# IPs
if [ -s "$LATEST_DIR/top_malicious.txt" ]; then
  grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$LATEST_DIR/top_malicious.txt" | awk '{print $1":"}' > malicious-ips.txt
else
  echo "[!] top_malicious.txt missing/empty - keeping previous malicious-ips.txt"
fi

# Domains from URLhaus, filtered for shared infrastructure (infra_allow.txt).
# A platform domain (github.com, cdn.discordapp.com, pastebin.com) is not an
# IOC - blocking it matches the platform instead of the payload, which is what
# broke rules 100101/100102. ioc_extract.py also fixes a parser bug: the
# URLhaus export has no header row, so the old code silently dropped the first
# IOC of every day. Suppressed hosts land in <day>/infra_suppressed.md.
if [ -s "$LATEST_DIR/urlhaus.csv" ]; then
  python3 ioc_extract.py domains "$LATEST_DIR/urlhaus.csv" malicious-domains.txt \
      --allow infra_allow.txt \
      --report "$LATEST_DIR/infra_suppressed.md"
else
  echo "[!] urlhaus.csv missing/empty - keeping previous malicious-domains.txt"
fi

# Hashes from ThreatFox (new API: value field is "ioc"; old export was
# "ioc_value"; also pulls hashes attached via malware_samples)
if [ -s "$LATEST_DIR/threatfox_recent.json" ]; then
python3 - "$LATEST_DIR/threatfox_recent.json" << 'PY'
import json, sys
path = sys.argv[1]
hashes = set()
with open(path) as f:
    data = json.load(f)
for entries in data.values():
    for item in entries:
        ioc_type = (item.get("ioc_type") or "").lower()
        # new API: "ioc"; legacy export: "ioc_value"
        value = (item.get("ioc") or item.get("ioc_value") or "").lower().strip()
        if ioc_type in ("md5_hash", "sha1_hash", "sha256_hash") and value:
            hashes.add(value)
        for s in item.get("malware_samples") or []:
            for k in ("md5_hash", "sha1_hash", "sha256_hash"):
                if s.get(k):
                    hashes.add(s[k].lower())
with open("malicious-hashes.txt", "w") as f:
    for h in sorted(hashes):
        f.write(h + ":\n")
print(f"Extracted {len(hashes)} hashes")
PY
else
  echo "[!] threatfox_recent.json missing/empty - keeping previous malicious-hashes.txt"
fi

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
      exit 1
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
