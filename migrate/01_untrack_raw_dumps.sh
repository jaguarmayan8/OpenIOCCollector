#!/usr/bin/env bash
# migrate/01_untrack_raw_dumps.sh
#
# ONE-TIME. Stops git tracking the raw feed dumps that made this repo >1 GB.
# Run this BEFORE 02_shrink_history.sh.
#
# It only changes the INDEX - the files stay on disk, so the local pipeline and
# the next collector run are unaffected.
set -euo pipefail
cd "$(dirname "$0")/.."

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "=== Finding tracked raw dumps ==="
git ls-files -z 'Output/*' 'malicious-*.txt.prev' > "$TMP/all.z"

python3 - "$TMP/all.z" "$TMP/untrack.z" <<'PY'
import re, sys

RAW = re.compile(
    r"/(urlhaus\.csv|threatfox_recent\.json|ssl_blacklist\.csv"
    r"|feodo_tracker\.txt|top_malicious\.txt|malwarebazaar_recent\.json)$"
    r"|malicious-(ips|domains|hashes)\.txt\.prev$"
)
src, dst = sys.argv[1], sys.argv[2]
paths = [p for p in open(src, "rb").read().split(b"\0") if p]
keep = [p for p in paths if RAW.search(p.decode()) or b"/cdb/" in p]
open(dst, "wb").write(b"\0".join(keep) + (b"\0" if keep else b""))
print(f"tracked files under Output/: {len(paths)}")
print(f"raw dumps + cdb/ to untrack:  {len(keep)}")
PY

COUNT=$(tr -cd '\0' < "$TMP/untrack.z" | wc -c)
if [ "$COUNT" -eq 0 ]; then
  echo "[i] Nothing to untrack - already clean"
  exit 0
fi

git rm --cached --quiet --pathspec-from-file="$TMP/untrack.z" --pathspec-file-nul
echo "[+] Unstaged $COUNT raw file(s) from the index (files remain on disk)"

git add .gitignore
git commit -m "Stop tracking raw feed dumps

Raw dumps (URLhaus CSV ~30 MB/day, ThreatFox JSON ~7 MB/day) added ~38 MB to
git history every day. They are now published as GitHub Release assets by
publish_raw.sh, and .gitignore prevents any 'git add Output/' from
re-tracking them. History rewrite follows in 02_shrink_history.sh."

echo
echo "=== Working tree status ==="
git status --short | head -20
echo
echo "Next: bash migrate/02_shrink_history.sh"
