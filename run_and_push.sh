#!/bin/bash
# Fail fast: any failed command, undefined variable, or failed pipeline stops
# the run BEFORE stale/partial data reaches Wazuh or GitHub.
set -euo pipefail

cd /home/chap/OpenIOCCollector || exit 1

echo "=== Starting IOC Collector ==="
# NOTE: the collector deliberately does NOT abort on partial failures - a
# single dead feed should not kill the run. Its exit code only signals
# "fewer than MIN_SUCCESSFUL_FEEDS feeds returned data".
/usr/bin/python3 collector.py

echo "=== Finding latest output directory ==="
LATEST_DIR=$(find Output -type d -name "$(date +%Y%m%d)" | sort | tail -1)

if [ -z "$LATEST_DIR" ]; then
  echo "ERROR: Could not find today's output directory"
  exit 1
fi

echo "Using directory: $LATEST_DIR"

echo "=== Building CDB lists ==="

# IPs
grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$LATEST_DIR/top_malicious.txt" | awk '{print $1":"}' > malicious-ips.txt

# Domains from URLhaus - parsed with csv.DictReader so quoted commas and
# column reordering (the authenticated export differs from the old keyless
# one) can't silently break the extraction.
python3 - "$LATEST_DIR/urlhaus.csv" << 'PY'
import csv, re, sys
host_re = re.compile(r"(?<=://)[^/:]+")
domains = set()
with open(sys.argv[1], newline="", errors="ignore") as f:
    rows = csv.reader(l for l in f if l.strip() and not l.startswith("#"))
    header = next(rows, None)
    url_idx = header.index("url") if header and "url" in (header or []) else 2
    for row in rows:
        if len(row) <= url_idx:
            continue
        for host in host_re.findall(row[url_idx]):
            if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", host):
                domains.add(host)
with open("malicious-domains.txt", "w") as f:
    for d in sorted(domains):
        f.write(d + ":\n")
print(f"Extracted {len(domains)} domains")
PY

# Hashes from ThreatFox (new API: value field is "ioc"; old export was
# "ioc_value"; also pulls hashes attached via malware_samples)
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

echo "IPs: $(wc -l < malicious-ips.txt)"
echo "Domains: $(wc -l < malicious-domains.txt)"
echo "Hashes: $(wc -l < malicious-hashes.txt)"

echo "=== Sanity check before pushing ==="
# A list that is EMPTY, or collapsed to a tiny fraction of its previous size,
# almost always means an upstream feed broke (410, auth expired, format
# change) - not that the internet got safer. Pushing that to Wazuh would
# silently blind rules 100100-100111. Previous snapshots are kept next to
# the lists (malicious-<type>.prev) for comparison and rollback.
MIN_FRACTION=50   # block push if new list < MIN_FRACTION% of previous
MIN_ABSOLUTE=10   # ... or if it has fewer entries than this

check_list() {
  local name="$1" file="$2" prev
  local count
  count=$(wc -l < "$file")
  if [ ! -f "$file" ]; then
    echo "ABORT: $file missing"
    exit 1
  fi
  if [ "$count" -lt "$MIN_ABSOLUTE" ]; then
    echo "ABORT: $file has only $count entries (< $MIN_ABSOLUTE) - upstream feed likely broken"
    exit 1
  fi
  prev="$file.prev"
  if [ -f "$prev" ]; then
    local prev_count
    prev_count=$(wc -l < "$prev")
    # only compare when the previous snapshot was itself non-trivial
    if [ "$prev_count" -ge "$MIN_ABSOLUTE" ]; then
      # integer percent: count*100/prev
      if [ $(( count * 100 / prev_count )) -lt "$MIN_FRACTION" ]; then
        echo "ABORT: $file collapsed from $prev_count to $count entries (< ${MIN_FRACTION}% of previous) - refusing to push"
        exit 1
      fi
    fi
  fi
  # update the rolling snapshot for the next run
  cp "$file" "$prev"
  echo "OK: $name ($count entries)"
}

check_list "malicious-ips"      malicious-ips.txt
check_list "malicious-domains"  malicious-domains.txt
check_list "malicious-hashes"   malicious-hashes.txt

echo "=== VirusTotal enrichment ==="
/usr/bin/python3 vt_enrich.py

echo "=== Copying lists to Wazuh Manager ==="

scp -o StrictHostKeyChecking=no malicious-ips.txt malicious-domains.txt malicious-hashes.txt masterchap@192.168.4.122:~/
ssh masterchap@192.168.4.122 "sudo /usr/local/bin/update-malicious-ips.sh"

echo "=== Generate dashboard ==="
/usr/bin/python3 generate_dashboard.py

echo "=== Pruning old output (retention) ==="
# Deletes Output day folders older than KEEP_DAYS (default 90; override:
#   /usr/bin/python3 prune_output.py 60   or   KEEP_DAYS=60 ...)
# Runs BEFORE the commit so deletions are pushed with today's update.
/usr/bin/python3 prune_output.py

echo "=== Committing and pushing to GitHub ==="
git add Output/ malicious-ips.txt malicious-domains.txt malicious-hashes.txt docs/index.html
git commit -m "Daily IOC update $(date +%Y-%m-%d)" || echo "No changes to commit"
git push

echo "=== Done ==="
