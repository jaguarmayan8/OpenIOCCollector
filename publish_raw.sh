#!/usr/bin/env bash
# publish_raw.sh - upload a day's raw feed dumps as GitHub Release assets.
#
# WHY THIS EXISTS
#   The raw dumps are the only large files in this project (URLhaus CSV ~30 MB
#   and ThreatFox JSON ~7 MB per day). Committing them put ~38 MB into git
#   history every single day, forever - deleting the working-tree copy with
#   prune_output.py reclaimed nothing, because the blob stays in the packfile.
#   Releases give the same public, immutable, directly-downloadable artifacts
#   at zero cost to clone size, and they can be pruned.
#
#   The files Wazuh consumes (malicious-*.txt) are still committed and still
#   covered by checksums.sha256 - this script never touches them.
#
# DEPENDENCIES
#   curl + python3 (both already required by this project). Deliberately does
#   NOT need the `gh` CLI or jq - neither is installed on a stock Kali box.
#   One code path, so it behaves identically on Kali and on the Actions runner.
#
# AUTH
#   GH_TOKEN or GITHUB_TOKEN with Contents: read+write (classic PAT: "repo"
#   scope; fine-grained: Contents = Read and write on this repository).
#
# USAGE
#   GH_TOKEN=ghp_xxx bash publish_raw.sh            # today (UTC)
#   DAY=20261119 bash publish_raw.sh                # a specific day
#   RAW_KEEP_DAYS=30 bash publish_raw.sh            # release retention
#   DRY_RUN=1 bash publish_raw.sh                   # show what would happen
#
# Exit status is 0 even when publishing fails: a release problem must never
# block the CDB-list commit that Wazuh depends on. Failures are reported
# loudly and end with "finished WITH ERRORS" - never a false "done".
set -uo pipefail
cd "$(dirname "$0")"

DAY="${DAY:-$(date -u +%Y%m%d)}"
RAW_KEEP_DAYS="${RAW_KEEP_DAYS:-30}"
DRY_RUN="${DRY_RUN:-0}"
TAG="iocs-${DAY}"

# Overridable only so the test harness can point at a local mock API.
API_BASE="${GH_API_BASE:-https://api.github.com}"
UPLOAD_BASE="${GH_UPLOAD_BASE:-https://uploads.github.com}"

RAW_FILES=(
  urlhaus.csv
  threatfox_recent.json
  ssl_blacklist.csv
  feodo_tracker.txt
  top_malicious.txt
  malwarebazaar_recent.json
)

warn() { echo "[!] $*" >&2; }
FAILED=0

PY=$(command -v python3 || true)
if [ -z "$PY" ]; then
  warn "python3 not found - cannot publish. Install python3 or skip this step."
  exit 0
fi

DAY_DIR=$(find Output -type d -name "$DAY" 2>/dev/null | sort | tail -1 || true)
if [ -z "${DAY_DIR}" ]; then
  warn "No Output day folder for ${DAY} - nothing to publish"
  exit 0
fi

TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
if [ -z "$TOKEN" ]; then
  warn "No GH_TOKEN / GITHUB_TOKEN - skipping raw-dump publishing (CDB lists are unaffected)"
  exit 0
fi

SLUG=$(git config --get remote.origin.url 2>/dev/null \
     | sed -E 's#^(git@|https://|http://)github\.com[:/]##; s#\.git$##' || true)
case "$SLUG" in
  */*) : ;;
  *) warn "Cannot determine owner/repo from 'git remote origin' - skipping publish"; exit 0 ;;
esac

ASSETS=()
for f in "${RAW_FILES[@]}"; do
  p="$DAY_DIR/$f"
  if [ -s "$p" ]; then
    ASSETS+=("$p")
    printf '[i] %-24s %8.1f KB\n' "$f" "$(awk "BEGIN{print $(stat -c%s "$p")/1024}")"
  else
    echo "[i] $f missing or empty - not uploaded"
  fi
done

if [ "${#ASSETS[@]}" -eq 0 ]; then
  warn "No non-empty raw dumps for ${DAY} - nothing to upload"
  exit 0
fi

if [ "$DRY_RUN" = "1" ]; then
  echo "[dry-run] repo=${SLUG} tag=${TAG} assets=${#ASSETS[@]} keep=${RAW_KEEP_DAYS}d api=${API_BASE}"
  exit 0
fi

NOTES="Unprocessed upstream feed dumps collected on ${DAY} (UTC).

These are the raw upstream files. The deduplicated lists that Wazuh consumes
are committed in the repository root:

| File | Consumer |
| --- | --- |
| \`malicious-ips.txt\` | Wazuh CDB, rule 100100 |
| \`malicious-domains.txt\` | Wazuh CDB, rules 100101 / 100102 |
| \`malicious-hashes.txt\` | Wazuh CDB, rules 100110 / 100111 |

Verify those against \`checksums.sha256\`. Releases older than ${RAW_KEEP_DAYS}
days are deleted automatically."

API="${API_BASE}/repos/${SLUG}"
UPLOAD="${UPLOAD_BASE}/repos/${SLUG}/releases"

api() {
  curl -sS -H "Authorization: Bearer ${TOKEN}" \
       -H "Accept: application/vnd.github+json" \
       -H "X-GitHub-Api-Version: 2022-11-28" \
       -H "User-Agent: OpenIOCCollector/2.0" "$@"
}

# json_get <field>   (reads JSON on stdin, prints the field or nothing)
json_get() {
  "$PY" -c 'import sys,json
try:
    d=json.load(sys.stdin)
except Exception:
    sys.exit(0)
v=d.get(sys.argv[1]) if isinstance(d,dict) else None
if v not in (None,""):
    print(v)' "$1"
}

# json_msg   (reads JSON on stdin, prints .message or nothing)
json_msg() {
  "$PY" -c 'import sys,json
try:
    d=json.load(sys.stdin)
except Exception:
    sys.exit(0)
if isinstance(d,dict) and d.get("message"):
    print(d["message"])'
}

echo "[i] Publishing to ${SLUG} as release ${TAG}"

# --- find or create the release --------------------------------------------
REL_ID=$(api "${API}/releases/tags/${TAG}" | json_get id)

if [ -n "$REL_ID" ]; then
  echo "[i] Release ${TAG} exists (id ${REL_ID}) - replacing assets"
else
  BODY=$("$PY" -c 'import json,sys
print(json.dumps({"tag_name":sys.argv[1],"name":sys.argv[2],"body":sys.argv[3],
                  "draft":False,"prerelease":False,"make_latest":"false"}))' \
        "$TAG" "Raw IOC dumps ${DAY}" "$NOTES")
  RESP=$(api -X POST "${API}/releases" -d "$BODY")
  REL_ID=$(printf '%s' "$RESP" | json_get id)
  if [ -z "$REL_ID" ]; then
    warn "Could not create release ${TAG}. API said: $(printf '%s' "$RESP" | json_msg)"
    warn "Check that the token has Contents: read+write on ${SLUG}."
    exit 0
  fi
  echo "[+] Created release ${TAG} (id ${REL_ID})"
fi

# --- upload assets (replace any same-named asset first) --------------------
ASSET_IDS=$(api "${API}/releases/${REL_ID}/assets?per_page=100" | "$PY" -c 'import sys,json
try:
    d=json.load(sys.stdin)
except Exception:
    d=[]
for a in (d if isinstance(d,list) else []):
    print("{}\t{}".format(a.get("name",""), a.get("id","")))')

for p in "${ASSETS[@]}"; do
  NAME=$(basename "$p")
  OLD_ID=$(printf '%s\n' "$ASSET_IDS" | awk -F'\t' -v n="$NAME" '$1==n {print $2; exit}')
  if [ -n "${OLD_ID:-}" ] && [ "$OLD_ID" != "null" ]; then
    api -X DELETE "${API}/releases/assets/${OLD_ID}" >/dev/null 2>&1 \
      && echo "[-] Removed old asset ${NAME}"
  fi
  RESP_FILE=$(mktemp)
  CODE=$(curl -sS -o "$RESP_FILE" -w '%{http_code}' -X POST \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/octet-stream" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    -H "User-Agent: OpenIOCCollector/2.0" \
    --data-binary @"$p" \
    "${UPLOAD}/${REL_ID}/assets?name=${NAME}" || echo 000)
  if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
    echo "[+] Uploaded ${NAME}"
  else
    FAILED=1
    warn "Upload of ${NAME} failed (HTTP ${CODE}): $(json_msg < "$RESP_FILE")"
  fi
  rm -f "$RESP_FILE"
done

# --- prune old raw-dump releases -------------------------------------------
if [ "${RAW_KEEP_DAYS}" -gt 0 ]; then
  CUTOFF=$(date -u -d "${RAW_KEEP_DAYS} days ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-"${RAW_KEEP_DAYS}"d +%Y-%m-%dT%H:%M:%SZ)
  echo "[i] Pruning raw-feed releases older than ${CUTOFF}"
  api "${API}/releases?per_page=100" | "$PY" -c 'import sys,json,re
cutoff=sys.argv[1]
try:
    d=json.load(sys.stdin)
except Exception:
    d=[]
for r in (d if isinstance(d,list) else []):
    tag=r.get("tag_name","")
    created=r.get("created_at","")
    if created and created < cutoff and re.fullmatch(r"iocs-\d{8}", tag):
        print("{}\t{}".format(r.get("id",""), tag))' "$CUTOFF" \
  | while IFS=$'\t' read -r id tag; do
      [ -z "${id:-}" ] && continue
      echo "[-] Deleting old release ${tag}"
      api -X DELETE "${API}/releases/${id}" >/dev/null 2>&1 || warn "delete failed for ${tag}"
    done
fi

if [ "$FAILED" -ne 0 ]; then
  warn "publish_raw.sh finished WITH ERRORS for ${DAY}. Raw dumps are still on local disk."
else
  echo "[+] publish_raw.sh done for ${DAY}"
fi
exit 0
