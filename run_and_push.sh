#!/bin/bash
# Kali cron entry point. All pipeline logic lives in build_lists.sh (shared
# with the GitHub Actions workflow) - this script only orchestrates:
#   collect -> build/guard/enrich/dashboard/prune -> push to Wazuh -> commit
#
# It no longer re-implements the CDB extraction or the staleness guard. The
# old duplicate copy had drifted and still wrote the .prev snapshots that were
# untracked in SIZE_FIX.md; a second parser is a second way to be wrong.
set -euo pipefail

cd "$(dirname "$0")" || exit 1

echo "=== Starting IOC Collector ==="
# The collector deliberately does NOT abort on partial failures - a single
# dead feed should not kill the run. Its exit code only signals "fewer than
# MIN_SUCCESSFUL_FEEDS feeds returned data".
/usr/bin/python3 collector.py

# Lists, guard, VT enrichment, dashboard, retention, checksums.
bash build_lists.sh

echo "=== Copying lists to Wazuh Manager ==="
# Kept for the push-style setup. If the manager runs the pull script
# (wazuh_pull_lists.sh) instead, comment these two lines out - the pull path
# verifies checksums.sha256, which is strictly better than scp.
scp -o StrictHostKeyChecking=no malicious-ips.txt malicious-domains.txt malicious-hashes.txt masterchap@192.168.4.122:~/
ssh masterchap@192.168.4.122 "sudo /usr/local/bin/update-malicious-ips.sh"

echo "=== Publishing raw dumps to a GitHub Release ==="
# Raw dumps are not committed any more (~38 MB/day in history). See SIZE_FIX.md.
# Skipped gracefully when gh / GH_TOKEN is unavailable.
GH_TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}" bash publish_raw.sh || true

echo "=== Committing and pushing to GitHub ==="
# .gitignore keeps the raw dumps out even though this adds the whole folder.
git add Output/ malicious-ips.txt malicious-domains.txt malicious-hashes.txt docs/index.html checksums.sha256
git commit -m "Daily IOC update $(date +%Y-%m-%d)" || echo "No changes to commit"
git push

echo "=== Done ==="
