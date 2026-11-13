#!/usr/bin/env bash
# pull-ioc-lists.sh - RUNS ON THE WAZUH MANAGER (root cron), not on Kali.
# Pulls the CDB lists from the OpenIOCCollector GitHub repo over HTTPS and
# installs them with the existing update script. Replaces the old
# collector->scp push (and its StrictHostKeyChecking=no).
#
# Install: cp wazuh_pull_lists.sh /usr/local/bin/pull-ioc-lists.sh
#          chmod +x /usr/local/bin/pull-ioc-lists.sh
# Cron (root):  crontab -e
#   30 5 * * * /usr/local/bin/pull-ioc-lists.sh >> /var/log/pull-ioc-lists.log 2>&1
# (05:30 UTC - about an hour after the Actions run starts, so fresh lists
#  are usually already pushed; if the run failed, the old lists simply stay.)
set -euo pipefail

REPO_RAW="https://raw.githubusercontent.com/jaguarmayan8/OpenIOCCollector/main"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

for f in malicious-ips.txt malicious-domains.txt malicious-hashes.txt checksums.sha256; do
  curl -fsSL --max-time 120 -o "$STAGE/$f" "$REPO_RAW/$f"
done

cd "$STAGE"
# Verify against the checksums committed by the pipeline - any tampering
# or truncated download aborts BEFORE anything is installed.
sha256sum -c checksums.sha256

# Install the same way the old scp flow did: files in /root, then the
# existing update script. Adjust the cp target if your update script
# expects the files somewhere else.
for f in malicious-ips.txt malicious-domains.txt malicious-hashes.txt; do
  cp "$f" "/root/$f"
done
/usr/local/bin/update-malicious-ips.sh
