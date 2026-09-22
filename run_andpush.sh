#!/bin/bash
cd /home/chap/OpenIOCCollector || exit 1

echo "=== Starting IOC Collector ==="
/usr/bin/python3 tweetfeed.py

echo "=== Normalizing IOCs ==="
/usr/bin/python3 normalize.py || echo "WARNING: normalize.py failed (continuing)"

echo "=== Creating updated malicious IP list ==="
LATEST_DIR=$(find Output -type d -name "$(date +%Y%m%d)" | sort | tail -1)
if [ -z "$LATEST_DIR" ]; then
    echo "ERROR: Could not find today's output directory"
    exit 1
fi

echo "Using directory: $LATEST_DIR"
grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$LATEST_DIR/top_malicious.txt" | awk '{print $1":"}' > malicious-ips.txt

WAZUH_HOST="192.168.4.122"
if ping -c 1 -W 2 "$WAZUH_HOST" >/dev/null 2>&1; then
    echo "=== Copying list to Wazuh Manager and updating CDB ==="
    scp -o StrictHostKeyChecking=no malicious-ips.txt masterchap@${WAZUH_HOST}:~/malicious-ips.txt
    ssh masterchap@${WAZUH_HOST} "sudo /usr/local/bin/update-malicious-ips.sh"
else
    echo "=== Wazuh $WAZUH_HOST not reachable — skip CDB copy ==="
fi

echo "=== Committing and pushing to GitHub ==="
git add Output/ malicious-ips.txt latest.json site/data/latest.json
git commit -m "Daily IOC update $(date +%Y-%m-%d)" || echo "No changes to commit"
git push
echo "=== Done ==="
