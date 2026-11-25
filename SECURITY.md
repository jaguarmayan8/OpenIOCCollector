# Security policy

## What this project handles

OpenIOCCollector fetches public threat-intelligence feeds and publishes the
resulting indicator lists. It handles two credentials:

- `ABUSECH_AUTH_KEY` — the free abuse.ch Auth-Key.
- `VT_API_KEY` — optional, only used for the VirusTotal sample.

Both are read from the environment, or from files that `.gitignore` refuses to
track (`.abusech_auth_key`, `.vt_api_key`). No key is ever written into the
repository, the dashboard, the release assets or the image layers
(`.dockerignore` excludes them explicitly).

## Reporting a vulnerability

Do **not** open a public issue for a security problem.

Open a private report through GitHub:
**[Security → Report a vulnerability](https://github.com/jaguarmayan8/OpenIOCCollector/security/advisories/new)**
on this repository. If that is unavailable to you, contact the maintainer
through the GitHub profile [@jaguarmayan8](https://github.com/jaguarmayan8).

Please include what the flaw allows, the smallest reproduction you have, and
whether it affects the published lists (a bad list is worse than a broken
build — it lands in someone's detection rules).

Expect an acknowledgement within a few days. This is a home-lab project with
one maintainer; there is no paid support and no bounty.

## Scope

In scope:

- The collector, extraction, dashboard and shell pipeline in this repository.
- The published lists: anything that could inject a false, attacker-chosen or
  misleading indicator into `malicious-*.txt`.
- Credential handling and the GitHub Actions workflow.
- The published container image.

Out of scope:

- The upstream feeds themselves — report those to abuse.ch, stamparm/ipsum or
  VirusTotal.
- Missing detections. A feed that does not list a given indicator is not a
  vulnerability in this project.
- Policy disagreements about blocking. The lists are data; what you block on
  is your decision.

## Verifying what you installed

Every published list is checksummed. Before trusting a copy:

```bash
sha256sum -c checksums.sha256
```

`docs/api/manifest.json` carries the same digests with the run's date and feed
health, so a consumer can verify a download without trusting the page it read
them from.
