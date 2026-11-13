#!/usr/bin/env python3
"""Retention pruning for OpenIOCCollector daily output.

Deletes Output/<year>/<year-month>/<yyyymmdd>/ day folders older than
KEEP_DAYS (default 90), then removes any year/month directories left empty.
Today's folder is never touched, and the script never deletes anything
outside Output/. Run it from run_and_push.sh BEFORE the git commit so the
deletions are pushed along with the day's update.

Usage:
    python3 prune_output.py [KEEP_DAYS]
    KEEP_DAYS=60 python3 prune_output.py      # env var also works
"""
import shutil
import sys
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
OUTPUT_ROOT = BASE / "Output"


def main() -> int:
    # CLI arg wins over env var wins over default.
    keep_days = 90
    if len(sys.argv) > 1:
        keep_days = int(sys.argv[1])
    elif sys.platform != "win32" and "KEEP_DAYS" in __import__("os").environ:
        keep_days = int(__import__("os").environ["KEEP_DAYS"])

    if not OUTPUT_ROOT.exists():
        print("No Output/ directory - nothing to prune")
        return 0

    cutoff = time.time() - keep_days * 86400
    today_dir = OUTPUT_ROOT / time.strftime("%Y") / time.strftime("%Y-%m") / time.strftime("%Y%m%d")

    deleted_dirs = 0
    freed_bytes = 0

    # Output/<year>/<year-month>/<yyyymmdd>
    for year_dir in sorted(OUTPUT_ROOT.iterdir()):
        if not year_dir.is_dir():
            continue
        for month_dir in sorted(year_dir.iterdir()):
            if not month_dir.is_dir():
                continue
            for day_dir in sorted(month_dir.iterdir()):
                if not day_dir.is_dir():
                    continue
                if day_dir == today_dir:
                    continue  # never delete today's output
                # Folder name IS the date (yyyymmdd) - parse it rather than
                # trusting mtime, which git checkouts/reset can alter.
                try:
                    day_time = time.mktime(
                        time.strptime(day_dir.name, "%Y%m%d"))
                except ValueError:
                    print(f"[!] Skipping unrecognized folder name: {day_dir}")
                    continue
                if day_time < cutoff:
                    size = sum(f.stat().st_size for f in day_dir.rglob("*") if f.is_file())
                    shutil.rmtree(day_dir)
                    deleted_dirs += 1
                    freed_bytes += size
                    print(f"[-] Pruned {day_dir.relative_to(BASE)} ({size / 1024 / 1024:.1f} MB)")

    # Remove now-empty month and year directories so the tree stays tidy.
    for year_dir in sorted(OUTPUT_ROOT.iterdir()):
        if not year_dir.is_dir():
            continue
        for month_dir in sorted(year_dir.iterdir()):
            if month_dir.is_dir() and not any(month_dir.iterdir()):
                month_dir.rmdir()
                print(f"[-] Removed empty {month_dir.relative_to(BASE)}")
        if not any(year_dir.iterdir()):
            year_dir.rmdir()
            print(f"[-] Removed empty {year_dir.relative_to(BASE)}")

    print(f"[+] Pruned {deleted_dirs} day folders, freed {freed_bytes / 1024 / 1024:.1f} MB (kept last {keep_days} days)")
    return 0


if __name__ == "__main__":
    sys.exit(main())


