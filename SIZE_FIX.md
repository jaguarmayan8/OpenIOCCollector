# Repo size fix — runbook

**Problem.** `Output/` held 1,046 MB of tracked files, and **1,003 MB (95.9%) of
that was raw upstream dumps**. Committing them added ~38 MB to git history every
day, permanently: `prune_output.py` deleted the working-tree copy after 90 days,
but the blob stays in the packfile forever, so pruning reclaimed nothing. Git
history is append-only for blobs — the only way to reclaim it is a rewrite.

**Target state.** The repo tracks only what a consumer needs (~2.3 MB of lists
plus a few KB of summaries per day). Raw dumps are published as GitHub Release
assets and kept 30 days there.

---

## What changed in this patch

| File | Change |
| --- | --- |
| `.gitignore` | Raw dump patterns — stops *any* `git add Output/` or `git add -A` from re-tracking them |
| `publish_raw.sh` | **new** — uploads the day's raw dumps to release `iocs-YYYYMMDD`, prunes releases older than `RAW_KEEP_DAYS` (30) |
| `prune_output.py` | Rewritten: two-tier retention. Raw dumps `RAW_KEEP_DAYS` (3), day folders / summaries `DERIVED_DAYS` (90). Adds `--dry-run` |
| `build_lists.sh` | Staleness guard now reads the previous list from `git show HEAD:<file>` instead of the tracked `.prev` snapshot — removes a duplicate ~2 MB blob per day. Single source of pipeline truth |
| `run_and_push.sh` | Delegates to `build_lists.sh` instead of duplicating the extraction + guard (the copies had already drifted) |
| `.github/workflows/collector.yml` | Adds the release-publishing step |
| `generate_dashboard.py` | "Today's raw output" now links to the release (the old `tree/main/Output/...` link would 404 once raw dumps leave git) |
| `migrate/01_untrack_raw_dumps.sh` | One-time: `git rm --cached` the raw dumps |
| `migrate/02_shrink_history.sh` | One-time: `git filter-repo` rewrite + repack |

Per-day history cost after this patch: **~2.3 MB of content** (dominated by
`malicious-ips.txt`, which delta-compresses well), versus ~40 MB before.

## Measured result

Run end-to-end on a fresh clone of `main` (2026-11-19):

| Metric | Before | After |
| --- | --- | --- |
| Tracked bytes | 1,046 MB | 33 MB |
| Tracked files | 870 | 417 |
| `.git` (full clone) | 144 MB | **35 MB** |
| Fresh `--depth 1` clone | 111 MB+ | **5 MB** `.git` / 36 MB tree |

`malicious-ips.txt` still has all 140,106 entries, `sha256sum -c
checksums.sha256` passes, and no raw dump remains in any commit.

The 33 MB that stays under `Output/` is legacy 2026-09 normalized output from
the old tweetfeed pipeline; current days contribute ~8 KB each (summary +
VT results), so it shrinks as those folders age out of the 90-day window.

---

## Prerequisites

Run every step **from inside the repository**. `cd ~/OpenIOCCollector` first —
`git apply`, `migrate/*` and `.git` all resolve relative to the current
directory, so running from `~` fails with *"not a git repository"*.

```bash
cd ~/OpenIOCCollector
git status                                         # must be clean
ls size-fix.patch                                  # if missing, see below
```

The patch is downloaded from the chat card and usually lands in `~/Downloads`:

```bash
mv ~/Downloads/size-fix.patch ~/OpenIOCCollector/  # adjust if it landed elsewhere
```

`git filter-repo` (step 3 only) — try these in order:

```bash
sudo apt install -y git-filter-repo       # Debian/Kali package
# if apt cannot find it:
pipx install git-filter-repo              # or: sudo pip3 install --break-system-packages git-filter-repo
```

`gh` is **not** required — `publish_raw.sh` falls back to the REST API with curl.

## Step 1 — apply and commit the untracking

```bash
cd ~/OpenIOCCollector
git apply --check size-fix.patch && git apply size-fix.patch
bash migrate/01_untrack_raw_dumps.sh
git push
```

The files stay on disk; only the index changes. `git status` after this should
show a normal clean tree.

## Step 2 — publish today's raw dumps (optional, recommended)

Needs a token, not the `gh` CLI: classic PAT with `repo` scope, or a
fine-grained token with **Contents: Read and write**. Create one under GitHub →
Settings → Developer settings → Personal access tokens.

```bash
cd ~/OpenIOCCollector
GH_TOKEN=ghp_yourtoken bash publish_raw.sh
```

No token handy? **Skip this step.** The files stay on disk (untracking never
deletes anything), and from tomorrow the Actions workflow publishes them
automatically. Only today's dumps would never become a release asset.

Check it landed: `gh release list`. The release is `iocs-YYYYMMDD`, marked as
**not** latest so it does not hijack the repo landing page.

## Step 3 — rewrite history (destructive, one time)

Do this from a **fresh clone** with the cron disabled. Requires
`pip3 install git-filter-repo`.

```bash
cd ~
git clone https://github.com/jaguarmayan8/OpenIOCCollector.git ioc-rewrite
cd ~/ioc-rewrite
bash migrate/02_shrink_history.sh
```

This step is **optional for stopping the bleed** — after step 1 the repo can no
longer grow by 38 MB/day. It is required only to reclaim the 144 MB already in
history.

It prints before/after `.git` sizes, strips the raw dumps out of every commit,
then expires the reflog and runs `git gc --prune=now --aggressive`.

```bash
git remote add origin https://github.com/jaguarmayan8/OpenIOCCollector.git
git push --force --all origin
git push --force --tags origin
```

### After the force-push

1. **Re-clone on every other machine** (Kali cron box, Wazuh box). A `git pull`
   into an old clone re-merges the removed blobs — it must be a fresh clone.
   ```bash
   mv ~/OpenIOCCollector ~/OpenIOCCollector.old && \
   git clone https://github.com/jaguarmayan8/OpenIOCCollector.git ~/OpenIOCCollector
   # copy back .abusech_auth_key and .vt_api_key, then delete the .old folder
   ```
2. **GitHub still stores the unreachable objects**, addressable by SHA, until it
   garbage collects. New clones are small either way, but to purge them fully
   open a support request: *"Please run `git gc` on
   `jaguarmayan8/OpenIOCCollector` to remove unreachable objects."*
3. Verify:
   ```bash
   git clone --depth 1 https://github.com/jaguarmayan8/OpenIOCCollector.git /tmp/check
   du -sh /tmp/check/.git
   ```

---

## Step 4 — keep it from coming back

Nothing else to do: `.gitignore` + the workflow's explicit `git add` paths cover
both cron entry points. To audit at any time:

```bash
git ls-files -z 'Output/*' | du -ch --files0-from=- | tail -1   # ~33 MB, falling as legacy folders age out
du -sh .git                                                     # low tens of MB
```

Optional (frees local disk on the Kali box, ~850 MB today):

```bash
python3 prune_output.py --raw-days 1 --derived-days 90 --dry-run   # preview
python3 prune_output.py --raw-days 1 --derived-days 90
```

---

## Bash 3.2 note

`publish_raw.sh` uses `date -d` with a BSD `date -v` fallback, so it runs on
both the Ubuntu runner and macOS. If you ever run it where neither works, set
`RAW_KEEP_DAYS=0` to skip release pruning.
