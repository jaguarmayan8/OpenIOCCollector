#!/usr/bin/env bash
# migrate/02_shrink_history.sh
#
# ONE-TIME, DESTRUCTIVE. Strips the raw feed dumps out of EVERY commit, which
# rewrites every commit SHA in this repository.
#
# Run 01_untrack_raw_dumps.sh and push that commit FIRST, so the tip of main is
# already clean before history is rewritten.
#
# Do not run this on the Kali cron box mid-run. Do it from a fresh clone, with
# the cron disabled, then re-clone on every machine afterwards.
#
# Requires git-filter-repo:  pip3 install git-filter-repo
set -euo pipefail
cd "$(dirname "$0")/.."

if ! git filter-repo --version >/dev/null 2>&1; then
  echo "ERROR: git-filter-repo not installed."
  echo "  pip3 install git-filter-repo      (or: apt-get install git-filter-repo)"
  exit 1
fi

if [ "$(git rev-parse --is-shallow-repository)" = "true" ]; then
  echo "Rejecting: shallow clone. Run 'git fetch --unshallow' first so the"
  echo "rewrite covers the whole history."
  exit 1
fi

echo "=== Before ==="
git count-objects -vH | sed 's/^/  /'
BEFORE=$(du -sm .git | cut -f1)

echo
echo "=== Rewriting history (this can take a few minutes) ==="
# fnmatch '*'' spans '/', so 'Output/*/<file>' matches every depth:
#   Output/20260811/urlhaus.csv
#   Output/2026/2026-11/20261119/urlhaus.csv
git filter-repo --force --invert-paths \
  --path-glob 'Output/*/urlhaus.csv' \
  --path-glob 'Output/*/threatfox_recent.json' \
  --path-glob 'Output/*/ssl_blacklist.csv' \
  --path-glob 'Output/*/feodo_tracker.txt' \
  --path-glob 'Output/*/top_malicious.txt' \
  --path-glob 'Output/*/malwarebazaar_recent.json' \
  --path-glob 'Output/*/cdb/*'

echo
echo "=== Repacking ==="
git reflog expire --expire=now --all
git gc --prune=now --aggressive

AFTER=$(du -sm .git | cut -f1)
echo
echo "=== After ==="
git count-objects -vH | sed 's/^/  /'
echo
echo "  .git: ${BEFORE} MB -> ${AFTER} MB"
echo
cat <<'NEXT'
=== Remaining manual steps ===
1. Re-add the remote (git-filter-repo drops it) and force-push:
     git remote add origin https://github.com/jaguarmayan8/OpenIOCCollector.git
     git push --force --all origin
     git push --force --tags origin

2. Every other clone (Kali cron box, Wazuh box) MUST be re-cloned.
   Do not `git pull` into an old clone - it will re-merge the removed blobs.

3. GitHub keeps unreachable objects addressable by SHA until it garbage
   collects. New clones and the repo size shown in the UI will be small, but
   to purge them completely open a support request ("Please run git gc on
   jaguarmayan8/OpenIOCCollector to remove unreachable objects").

4. Verify from a clean checkout:
     git clone --depth 1 https://github.com/jaguarmayan8/OpenIOCCollector.git /tmp/check
     du -sh /tmp/check /tmp/check/.git
NEXT
