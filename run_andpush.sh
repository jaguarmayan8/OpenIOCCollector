#!/bin/bash

cd /home/chap/TwitterIoCsfeed || exit 1

echo "=== Starting IOC Collector ==="
/usr/bin/python3 tweetfeed.py

echo "=== Creating updated malicious IP list ==="
LATEST_DIR=$(find Output -type d -name "$(date +%Y%m%d)" | sort | tail -1)

if [ -z "$LATEST_DIR" ]; then
  echo "ERROR: Could not find today's output directory"
  exit 1
fi

echo "Using directory: $LATEST_DIR"

grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$LATEST_DIR/top_malicious.txt" | awk '{print $1":"}' > malicious-ips.txt

echo "=== Copying list to Wazuh Manager and updating CDB ==="
scp -o StrictHostKeyChecking=no malicious-ips.txt masterchap@192.168.4.35:~/malicious-ips.txt
ssh masterchap@192.168.4.35 "sudo /usr/local/bin/update-malicious-ips.sh"

echo "=== Committing and pushing to GitHub ==="
git add Output/ malicious-ips.txt
git commit -m "Daily IOC update $(date +%Y-%m-%d)" || echo "No changes to commit"
git push

echo "=== Done ==="
