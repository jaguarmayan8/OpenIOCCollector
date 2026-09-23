#!/bin/bash
cd /home/chap/OpenIOCCollector || exit 1

echo "=== Starting IOC Collector ==="
/usr/bin/python3 tweetfeed.py

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

# Domains from URLhaus
grep -v '^#' "$LATEST_DIR/urlhaus.csv" | \
awk -F',' '{print $3}' | \
sed 's/"//g' | \
grep -oP '(?<=://)[^/:]+' | \
grep -vE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
sort -u | \
sed 's/$/:/' > malicious-domains.txt

# Hashes from ThreatFox
python3 - "$LATEST_DIR/threatfox_recent.json" << 'PY'
import json, sys
path = sys.argv[1]
hashes = set()
with open(path) as f:
    data = json.load(f)
for entries in data.values():
    for item in entries:
        ioc_type = item.get("ioc_type", "")
        ioc_value = item.get("ioc_value", "")
        if ioc_type in ("md5_hash", "sha1_hash", "sha256_hash") and ioc_value:
            hashes.add(ioc_value.lower())
with open("malicious-hashes.txt", "w") as f:
    for h in sorted(hashes):
        f.write(h + ":\n")
print(f"Extracted {len(hashes)} hashes")
PY

echo "IPs: $(wc -l < malicious-ips.txt)"
echo "Domains: $(wc -l < malicious-domains.txt)"
echo "Hashes: $(wc -l < malicious-hashes.txt)"

echo "=== VirusTotal enrichment ==="
/usr/bin/python3 vt_enrich.py

echo "=== Copying lists to Wazuh Manager ==="

scp -o StrictHostKeyChecking=no malicious-ips.txt malicious-domains.txt malicious-hashes.txt masterchap@192.168.4.122:~/
ssh masterchap@192.168.4.122 "sudo /usr/local/bin/update-malicious-ips.sh"

echo "=== Committing and pushing to GitHub ==="
git add Output/ malicious-ips.txt malicious-domains.txt malicious-hashes.txt
git commit -m "Daily IOC update $(date +%Y-%m-%d)" || echo "No changes to commit"
git push

echo "=== Done ==="
