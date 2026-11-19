#!/usr/bin/env python3
"""Two-tier retention pruning for OpenIOCCollector.

WHY TWO TIERS
  The files under Output/ fall into two very different cost classes:

    raw      urlhaus.csv (~30 MB/day), threatfox_recent.json (~7 MB/day),
             top_malicious.txt (~2.2 MB/day), ssl_blacklist.csv (~0.85 MB/day)
             These exist only so the pipeline can be re-run for that day.
             Published as GitHub Release assets by publish_raw.sh, so the
             local copy is disposable: keep RAW_DAYS (default 3).

    derived  daily_summary.md, vt_enrichment.json / .md, cdb/*
             A few KB per day and worth keeping as history: DERIVED_DAYS
             (default 90).

  The old version deleted whole day folders after 90 days, which left
  ~850 MB of raw dumps on disk *and* did nothing about git history. Raw dumps
  are no longer tracked by git at all (see .gitignore / SIZE_FIX.md), so this
  script only has to keep the local disk honest.

USAGE
    python3 prune_output.py                       # 3 raw / 90 derived
    python3 prune_output.py --raw-days 7 --derived-days 180
    python3 prune_output.py --dry-run             # report only
    KEEP_DAYS=60 python3 prune_output.py          # legacy: derived days
    RAW_KEEP_DAYS=5 python3 prune_output.py

  Today's folder is never touched, and nothing outside Output/ is ever deleted.
"""
import argparse
import os
import re
import shutil
import sys
import time
from datetime import date, datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent
OUTPUT_ROOT = BASE / "Output"

# Files that are large, reproducible from upstream, and published as release
# assets. Keep these for days of RAW_DAYS.
RAW_FILES = frozenset({
    "urlhaus.csv",
    "threatfox_recent.json",
    "ssl_blacklist.csv",
    "feodo_tracker.txt",
    "top_malicious.txt",
    "malwarebazaar_recent.json",
})

DAY_DIR_RE = re.compile(r"^\d{8}$")


def dir_date(day_dir: Path) -> date:
    """Day folders are named yyyymmdd - trust the name, not mtime (git
    checkouts and rsync resets scramble mtimes)."""
    try:
        return datetime.strptime(day_dir.name, "%Y%m%d").date()
    except ValueError:
        return datetime.fromtimestamp(day_dir.stat().st_mtime).date()


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def iter_day_dirs() -> list[Path]:
    if not OUTPUT_ROOT.exists():
        return []
    return sorted(
        d for d in OUTPUT_ROOT.rglob("*")
        if d.is_dir() and DAY_DIR_RE.match(d.name)
    )


def prune_raw_files(day_dir: Path, dry_run: bool) -> tuple[int, int]:
    removed = freed = 0
    for f in sorted(day_dir.iterdir()):
        if not f.is_file() or f.name not in RAW_FILES:
            continue
        size = f.stat().st_size
        if not dry_run:
            f.unlink()
        removed += 1
        freed += size
    return removed, freed


def remove_empty_dirs(dry_run: bool) -> None:
    """Drop month/year folders left empty so the tree stays browsable."""
    if not OUTPUT_ROOT.exists():
        return
    for d in sorted(OUTPUT_ROOT.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if not d.is_dir() or not DAY_DIR_RE.match(d.name):
            continue
        try:
            if not any(d.iterdir()):
                if not dry_run:
                    d.rmdir()
                print(f"[-] Removed empty {d.relative_to(BASE)}")
        except OSError:
            pass


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--raw-days", type=int,
                    default=int(os.environ.get("RAW_KEEP_DAYS", 3)),
                    help="days to keep large raw feed dumps (default 3)")
    ap.add_argument("--derived-days", type=int,
                    default=int(os.environ.get("KEEP_DAYS", 90)),
                    help="days to keep day folders / summaries (default 90)")
    ap.add_argument("legacy_keep_days", nargs="?", type=int, default=None,
                    help=argparse.SUPPRESS)  # old positional form
    ap.add_argument("--dry-run", action="store_true",
                    help="report what would be deleted, delete nothing")
    args = ap.parse_args()

    derived_days = args.legacy_keep_days if args.legacy_keep_days is not None else args.derived_days
    raw_days = args.raw_days
    if raw_days > derived_days:
        print(f"[!] --raw-days ({raw_days}) > --derived-days ({derived_days}); clamping")
        raw_days = derived_days

    today = date.today()
    today_dir = OUTPUT_ROOT / time.strftime("%Y") / time.strftime("%Y-%m") / time.strftime("%Y%m%d")

    day_dirs = iter_day_dirs()
    if not day_dirs:
        print("No Output day folders - nothing to prune")
        return 0

    dropped_dirs = dropped_files = 0
    freed = 0

    for day_dir in day_dirs:
        if day_dir == today_dir:
            continue  # never touch today
        age = (today - dir_date(day_dir)).days
        if age < 0:
            continue  # future-dated folder: leave it alone

        if age > derived_days:
            size = sum(f.stat().st_size for f in day_dir.rglob("*") if f.is_file())
            if not args.dry_run:
                shutil.rmtree(day_dir)
            dropped_dirs += 1
            freed += size
            print(f"[-] {'Would prune' if args.dry_run else 'Pruned'} day folder "
                  f"{day_dir.relative_to(BASE)} ({age}d old, {human(size)})")
        elif age > raw_days:
            n, b = prune_raw_files(day_dir, args.dry_run)
            if n:
                dropped_files += n
                freed += b
                print(f"[-] {'Would drop' if args.dry_run else 'Dropped'} {n} raw dump(s) "
                      f"from {day_dir.relative_to(BASE)} ({age}d old, {human(b)})")

    remove_empty_dirs(args.dry_run)

    verb = "Would free" if args.dry_run else "Freed"
    print(f"[+] {'Would prune' if args.dry_run else 'Pruned'} {dropped_dirs} day folder(s), "
          f"{dropped_files} raw dump(s); {verb} {human(freed)} "
          f"(raw>{raw_days}d, derived>{derived_days}d)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
