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

echo "=== Wazuh lists ==="
# The PUSH model is opt-in. The default is the pull model: the manager runs
# wazuh_pull_lists.sh and verifies checksums.sha256, so nothing happens here.
# Set WAZUH_PUSH=1 in the cron environment to push over SSH instead.
#
# Failure is deliberately non-fatal. Under `set -e` the old inline scp/ssh pair
# aborted this script when the manager was off - before the git push below - so
# a sleeping LAN box silently stopped the GitHub publish as well.
if [ "${WAZUH_PUSH:-0}" = "1" ]; then
  bash wazuh_push.sh || echo "WARNING: Wazuh push failed - continuing to GitHub publish"
else
  echo "Skipped (pull model). WAZUH_PUSH=1 enables the SSH push."
fi

echo "=== Publishing raw dumps to a GitHub Release ==="
# Raw dumps are not committed any more (~38 MB/day in history). See SIZE_FIX.md.
# Skipped gracefully when gh / GH_TOKEN is unavailable.
GH_TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}" bash publish_raw.sh || true

echo "=== Committing and pushing to GitHub ==="
# .gitignore keeps the raw dumps out even though this adds the whole folder.
git add Output/ malicious-ips.txt malicious-domains.txt malicious-hashes.txt docs/index.html checksums.sha256
git commit -m "Daily IOC update $(date +%Y-%m-%d)" || echo "No changes to commit"
git push || {
  echo "=== push rejected - rebasing on origin/main ==="
  git pull --rebase --autostash --no-edit origin main && git push
}

echo "=== Done ==="
