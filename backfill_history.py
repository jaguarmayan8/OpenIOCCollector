#!/usr/bin/env python3
"""Rebuild docs/history.json from the repository's own git history.

The daily pipeline appends one point per run, so the chart starts empty on the
day that change lands. Everything needed to rebuild the earlier points is
already in git - every commit touched the published lists - so this script can
reconstruct them instead of starting the trend at day one.

Usage:
    python3 backfill_history.py --days 90          # last 90 daily commits
    python3 backfill_history.py --days 90 --dry-run

Run it once after cloning; the GitHub Actions job keeps appending afterwards.
It never invents a point: a day without a committed list is skipped.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from generate_dashboard import indicator_key

BASE = Path(__file__).resolve().parent
LISTS = {
    "ips": "malicious-ips.txt",
    "domains": "malicious-domains.txt",
    "hashes": "malicious-hashes.txt",
}
HISTORY = BASE / "docs" / "history.json"
MAX_POINTS = 400


def git(*args, timeout=180):
    res = subprocess.run(["git", "-C", str(BASE), *args],
                         capture_output=True, text=True, timeout=timeout)
    if res.returncode != 0:
        raise RuntimeError("git %s failed: %s" % (" ".join(args), res.stderr.strip()))
    return res.stdout


def lines_at(commit, name):
    """The list at `commit` as a set of lines; empty set when it did not exist."""
    try:
        out = git("show", "%s:%s" % (commit, name))
    except RuntimeError:
        return set()
    # Keys, not raw lines: the provenance tail changed format on 2026-11-23
    # ("1.0.164.165:" -> "1.0.164.165:ipsum") and a line-level diff called that
    # a 100% turnover of the corpus.
    keys = (indicator_key(ln) for ln in out.splitlines())
    return {k for k in keys if k}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=90,
                    help="how many daily commits to walk back (default 90)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    # One commit per day: the daily job commits once, and a manual push in
    # between must not create a second point for the same date.
    log = git("log", "--date=short", "--pretty=%H %ad", "--", *LISTS.values())
    seen, commits = set(), []
    for line in log.splitlines():
        sha, day = line.split()[:2]
        if day in seen:
            continue
        seen.add(day)
        commits.append((sha, day))
        if len(commits) >= args.days:
            break
    commits.reverse()          # oldest first

    points = []
    prev_sets = None
    for sha, day in commits:
        sets = {key: lines_at(sha, name) for key, name in LISTS.items()}
        counts = {key: len(v) for key, v in sets.items()}
        entry = {
            "date": day,
            **counts,
            "published": sum(counts.values()),
            "raw": None,
            "new": None,
            "dropped": None,
            "source": "backfill",
        }
        if prev_sets is not None:
            # Set difference, not a subtraction of sizes: a list that grew by
            # 11k can still have dropped 300 indicators, and "dropped" must not
            # come out negative.
            entry["new"] = sum(len(sets[k] - prev_sets[k]) for k in sets)
            entry["dropped"] = sum(len(prev_sets[k] - sets[k]) for k in sets)
        points.append(entry)
        prev_sets = sets
        print("%s  published=%d  +%s/-%s" % (
            day, entry["published"], entry["new"], entry["dropped"]), file=sys.stderr)

    points = points[-MAX_POINTS:]
    if args.dry_run:
        print(json.dumps(points[-3:], indent=2))
        return 0

    existing = []
    if HISTORY.exists():
        try:
            existing = json.loads(HISTORY.read_text(encoding="utf-8"))
        except ValueError:
            existing = []
    by_date = {e["date"]: e for e in existing if isinstance(e, dict) and e.get("date")}
    for e in points:                      # live points win over backfilled ones
        by_date.setdefault(e["date"], e)
    merged = sorted(by_date.values(), key=lambda e: e["date"])[-MAX_POINTS:]

    HISTORY.parent.mkdir(parents=True, exist_ok=True)
    HISTORY.write_text(json.dumps(merged, indent=0) + "\n", encoding="utf-8")
    print("Wrote %s (%d points, %s → %s)" % (
        HISTORY, len(merged), merged[0]["date"], merged[-1]["date"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
