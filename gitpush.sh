#!/bin/bash
# Docker-based cron entry point: collect inside the container, then run the
# SAME host pipeline as run_and_push.sh (build_lists.sh), then commit.
#
# This script used to be a third copy of the pipeline: it ran `docker compose
# up -d` (against a Dockerfile whose CMD pointed at a file that does not exist)
# and then committed ONLY Output/, so the CDB lists, dashboard and checksums
# were never published on this path. All of that now lives in build_lists.sh,
# which is also what GitHub Actions calls - one implementation, one behaviour.
set -uo pipefail

cd "$(dirname "$0")" || exit 1

LOG_FILE="$PWD/cron.log"

{
  echo "===== $(date) ====="
  echo "$(date) - Starting collector (docker)..."

  # A one-shot job: `run --rm`, not `up -d`. The collector's exit code is
  # deliberately NOT fatal - run_and_push.sh treats a partial feed failure as
  # non-fatal too, and build_lists.sh's staleness guard is what decides whether
  # the resulting lists are safe to publish.
  if docker compose run --rm --build ioc-collector; then
    echo "$(date) - Collector finished"
  else
    echo "$(date) - WARNING: collector exited non-zero - build_lists.sh guard decides"
  fi

  echo "$(date) - Building lists / dashboard / checksums..."
  if ! bash build_lists.sh; then
    echo "$(date) - ERROR: build_lists.sh failed - nothing published"
    exit 1
  fi

  # Guard: the container and the host must agree on "today". They diverge when
  # the container runs in UTC and the host is on local time, which makes the
  # build above abort on a missing folder. Fail loudly instead of pushing
  # yesterday's numbers.
  if [ ! -d "Output/$(date +%Y)/$(date +%Y-%m)/$(date +%Y%m%d)" ]; then
    echo "$(date) - ERROR: no Output folder for local today ($(date +%Y%m%d)) -"
    echo "  container/host date mismatch. Check the /etc/localtime mount."
    exit 1
  fi

  echo "$(date) - Committing..."
  git add Output/ malicious-ips.txt malicious-domains.txt malicious-hashes.txt \
          docs/index.html checksums.sha256
  if git diff --cached --quiet; then
    echo "$(date) - No new files to push"
  else
    git commit -m "Daily IOC update $(date -u +%Y-%m-%d)"
    git push origin main
    echo "$(date) - Pushed to GitHub"
  fi

  echo "$(date) - Job finished"
} >> "$LOG_FILE" 2>&1
