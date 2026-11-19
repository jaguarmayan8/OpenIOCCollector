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
# AUTH
#   Needs only a token: GH_TOKEN or GITHUB_TOKEN, with Contents: read+write
#   (classic PAT: "repo" scope). The `gh` CLI is used when installed, otherwise
#   this falls back to the REST API via curl - so it works on a bare Kali box.
#
# USAGE
#   GH_TOKEN=ghp_xxx bash publish_raw.sh            # today (UTC)
#   DAY=20261119 bash publish_raw.sh                # a specific day
#   RAW_KEEP_DAYS=30 bash publish_raw.sh            # release retention
#   DRY_RUN=1 bash publish_raw.sh                   # show what would happen
#
# Exit status is 0 even when publishing fails: a release problem must never
# block the CDB-list commit that Wazuh depends on. Failures are logged loudly.
set -uo pipefail
cd "$(dirname "$0")"

DAY="${DAY:-$(date -u +%Y%m%d)}"
RAW_KEEP_DAYS="${RAW_KEEP_DAYS:-30}"
DRY_RUN="${DRY_RUN:-0}"
TAG="iocs-${DAY}"

RAW_FILES=(
  urlhaus.csv
  threatfox_recent.json
  ssl_blacklist.csv
  feodo_tracker.txt
  top_malicious.txt
  malwarebazaar_recent.json
)

warn() { echo "[!] $*"; }

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
if [ -z "$SLUG" ]; then
  warn "Cannot determine owner/repo from 'git remote origin' - skipping publish"
  exit 0
fi

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
  echo "[dry-run] repo=${SLUG} tag=${TAG} assets=${#ASSETS[@]} keep=${RAW_KEEP_DAYS}d"
  exit 0
fi

NOTES="Unprocessed upstream feed dumps collected on ${DAY} (UTC).

These are the raw upstream files. The deduplicated lists that Wazuh consumes
are committed in the repository root:

| File | Consumer |
| --- | --- |
| \`malicious-ips.txt\` | Wazuh CDB, rule 100100 |
| \`malicious-domains.txt\` | Wazuh CDB, rules 100101 / 100102 |
| \`malicious-hashes.txt\` | Wazuh CDB, rules 110100 / 100111 |

Verify those against \`checksums.sha256\`. Releases older than ${RAW_KEEP_DAYS}
days are deleted automatically."

# ---------------------------------------------------------------------------
# Preferred path: gh CLI (what the GitHub Actions workflow uses)
# ---------------------------------------------------------------------------
if [ "${NO_GH:-0}" != "1" ] && command -v gh >/dev/null 2>&1; then
  export GH_TOKEN="$TOKEN"
  FAILED=0
  if gh release view "$TAG" >/dev/null 2>&1; then
    if gh release upload "$TAG" "${ASSETS[@]}" --clobber; then
      echo "[+] Updated release ${TAG}"
    else
      warn "gh release upload FAILED for ${TAG}"; FAILED=1
    fi
  else
    if gh release create "$TAG" "${ASSETS[@]}" --title "Raw IOC dumps ${DAY}" \
        --latest=false --notes "$NOTES"; then
      echo "[+] Created release ${TAG}"
    else
      warn "gh release create FAILED for ${TAG}"; FAILED=1
    fi
  fi
  if [ "$RAW_KEEP_DAYS" -gt 0 ]; then
    CUTOFF=$(date -u -d "${RAW_KEEP_DAYS} days ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
          || date -u -v-"${RAW_KEEP_DAYS}"d +%Y-%m-%dT%H:%M:%SZ)
    gh release list --limit 200 --json tagName,createdAt \
      | jq -r --arg c "$CUTOFF" '.[] | select(.createdAt < $c) | .tagName' 2>/dev/null \
      | while read -r old; do
          case "$old" in
            iocs-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9])
              echo "[-] Deleting old release $old"; gh release delete "$old" --yes --cleanup-tag ;;
          esac
        done
  fi
  if [ "${FAILED:-0}" -ne 0 ]; then
    warn "publish_raw.sh finished WITH ERRORS for ${DAY} (see above). The raw dumps are still on local disk."
    warn "Most likely cause: the token lacks Contents: read+write, or expired."
  else
    echo "[+] publish_raw.sh done for ${DAY}"
  fi
  exit 0
fi

# ---------------------------------------------------------------------------
# Fallback: REST API via curl (no gh installed)
# ---------------------------------------------------------------------------
echo "[i] gh CLI not found - using the GitHub REST API via curl"
API="https://api.github.com/repos/${SLUG}"
UPLOAD="https://uploads.github.com/repos/${SLUG}/releases"
UA="OpenIOCCollector/2.0"

api() {
  curl -sS -H "Authorization: Bearer ${TOKEN}" \
       -H "Accept: application/vnd.github+json" \
       -H "X-GitHub-Api-Version: 2022-11-28" \
       -H "User-Agent: ${UA}" "$@"
}

api_code() {
  curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${TOKEN}" \
       -H "Accept: application/vnd.github+json" \
       -H "X-GitHub-Api-Version: 2022-11-28" \
       -H "User-Agent: ${UA}" "$@"
}

REL_JSON=$(api "${API}/releases/tags/${TAG}" 2>/dev/null || true)
REL_ID=$(printf '%s' "$REL_JSON" | jq -r '.id // empty' 2>/dev/null || true)
FAILED=0

if [ -n "$REL_ID" ]; then
  echo "[i] Release ${TAG} exists (id ${REL_ID}) - replacing assets"
else
  BODY=$(jq -n --arg tag "$TAG" --arg name "Raw IOC dumps ${DAY}" --arg body "$NOTES" \
    '{tag_name:$tag, name:$name, body:$body, draft:false, prerelease:false, make_latest:"false"}')
  REL_JSON=$(api -X POST "${API}/releases" -d "$BODY" 2>/dev/null || true)
  REL_ID=$(printf '%s' "$REL_JSON" | jq -r '.id // empty' 2>/dev/null || true)
  if [ -z "$REL_ID" ]; then
    warn "Could not create release ${TAG}. API said: $(printf '%s' "$REL_JSON" | jq -r '.message? // "no message"' 2>/dev/null)"
    warn "Check that the token has Contents: read+write on ${SLUG}."
    exit 0
  fi
  echo "[+] Created release ${TAG} (id ${REL_ID})"
fi

# Existing assets with the same name block re-upload; delete them first.
EXISTING=$(api "${API}/releases/${REL_ID}/assets?per_page=100" 2>/dev/null || true)
for p in "${ASSETS[@]}"; do
  NAME=$(basename "$p")
  OLD_ID=$(printf '%s' "$EXISTING" | jq -r --arg n "$NAME" '.[]? | select(.name==$n) | .id' 2>/dev/null | head -1)
  if [ -n "$OLD_ID" ] && [ "$OLD_ID" != "null" ]; then
    api -X DELETE "${API}/releases/assets/${OLD_ID}" >/dev/null 2>&1 && echo "[-] Removed old asset ${NAME}"
  fi
  CODE=$(curl -sS -o /tmp/_rel_up.json -w '%{http_code}' -X POST \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/octet-stream" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    -H "User-Agent: ${UA}" \
    --data-binary @"$p" \
    "${UPLOAD}/${REL_ID}/assets?name=${NAME}" || echo 000)
  if [ "$CODE" = "201" ] || [ "$CODE" = "200" ]; then
    echo "[+] Uploaded ${NAME}"
  else
    FAILED=1
    warn "Upload of ${NAME} failed (HTTP ${CODE}): $(jq -r '.message? // ""' /tmp/_rel_up.json 2>/dev/null)"
  fi
done

# Prune old raw-dump releases.
if [ "$RAW_KEEP_DAYS" -gt 0 ]; then
  CUTOFF=$(date -u -d "${RAW_KEEP_DAYS} days ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-"${RAW_KEEP_DAYS}"d +%Y-%m-%dT%H:%M:%SZ)
  echo "[i] Pruning raw-feed releases older than ${CUTOFF}"
  api "${API}/releases?per_page=100" 2>/dev/null \
    | jq -r --arg c "$CUTOFF" '.[]? | select(.created_at < $c) | select(.tag_name|test("^iocs-[0-9]{8}$")) | "\(.id) \(.tag_name)"' 2>/dev/null \
    | while read -r id tag; do
        [ -z "$id" ] && continue
        echo "[-] Deleting old release ${tag}"
        api -X DELETE "${API}/releases/${id}" >/dev/null 2>&1 || warn "delete failed for ${tag}"
      done
fi

echo "[+] publish_raw.sh done for ${DAY}"
