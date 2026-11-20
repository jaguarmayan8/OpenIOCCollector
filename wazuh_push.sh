#!/usr/bin/env bash
# wazuh_push.sh - push the CDB lists to a Wazuh manager over SSH (opt-in).
#
# The DEFAULT deployment is the pull model: wazuh_pull_lists.sh runs on the
# manager, fetches the lists from GitHub and verifies checksums.sha256. This
# script exists only for the push-style setup, and only runs when WAZUH_PUSH=1.
#
# Two things it guarantees that the old inline scp/ssh pair did not:
#   1. It never aborts the caller. The manager being switched off must not stop
#      the GitHub publish that follows in run_and_push.sh.
#   2. Host keys are actually verified. The old call passed
#      StrictHostKeyChecking=no, which accepts ANY key presented - so a spoofed
#      manager would have been trusted silently. Checking here is strict, and
#      the one-time trust step is printed instead of skipped.
#
# Env:
#   WAZUH_PUSH=1           required; enable the push
#   WAZUH_HOST             user@host (default masterchap@192.168.4.122)
#   WAZUH_REMOTE_CMD       command run on the manager
#                          (default sudo /usr/local/bin/update-malicious-ips.sh)
#   WAZUH_KNOWN_HOSTS      known_hosts file (default ~/.ssh/known_hosts)
#   WAZUH_SSH_KEY          optional private key (-i)
#   WAZUH_CONNECT_TIMEOUT  seconds (default 15)
#
# Exit: 0 pushed or intentionally skipped, 2 a list is missing/empty,
#       3 host key not trusted, 4 transfer or remote command failed.
set -uo pipefail

if [ "${WAZUH_PUSH:-0}" != "1" ]; then
  echo "Wazuh push: skipped (WAZUH_PUSH is not 1 - pull model)"
  exit 0
fi

cd "$(dirname "$0")" || exit 4

LISTS=(malicious-ips.txt malicious-domains.txt malicious-hashes.txt)
for f in "${LISTS[@]}"; do
  if [ ! -s "$f" ]; then
    echo "Wazuh push: ERROR $f is missing or empty - refusing to push a partial set"
    exit 2
  fi
done

HOST="${WAZUH_HOST:-masterchap@192.168.4.122}"
REMOTE_CMD="${WAZUH_REMOTE_CMD:-sudo /usr/local/bin/update-malicious-ips.sh}"
KNOWN_HOSTS="${WAZUH_KNOWN_HOSTS:-$HOME/.ssh/known_hosts}"
TIMEOUT="${WAZUH_CONNECT_TIMEOUT:-15}"
HOST_ONLY="${HOST#*@}"

# BatchMode=yes so a password prompt can never hang an unattended cron run.
OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=yes
      -o "UserKnownHostsFile=$KNOWN_HOSTS" -o "ConnectTimeout=$TIMEOUT")
if [ -n "${WAZUH_SSH_KEY:-}" ]; then
  OPTS+=(-i "$WAZUH_SSH_KEY")
fi

# Fail with instructions rather than with ssh's 20-line host-key wall.
if ! ssh-keygen -F "$HOST_ONLY" -f "$KNOWN_HOSTS" >/dev/null 2>&1; then
  cat <<EOF
Wazuh push: host key for $HOST_ONLY is not in $KNOWN_HOSTS - refusing to connect.

Trust it once, after checking the fingerprint against the manager itself:
  on the manager:  ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
  on this host:    ssh-keyscan -t ed25519 $HOST_ONLY >> $KNOWN_HOSTS
                   (compare the key above with the manager's before trusting it)

The lists were still built and published to GitHub; the pull model needs none
of this. Set WAZUH_PUSH=0 to silence this check entirely.
EOF
  exit 3
fi

echo "Wazuh push: $HOST <- ${LISTS[*]}"
if ! scp "${OPTS[@]}" "${LISTS[@]}" "$HOST:~/"; then
  echo "Wazuh push: ERROR scp failed (host unreachable?)"
  exit 4
fi
if ! ssh "${OPTS[@]}" "$HOST" "$REMOTE_CMD"; then
  echo "Wazuh push: ERROR remote command failed: $REMOTE_CMD"
  exit 4
fi
echo "Wazuh push: done"
