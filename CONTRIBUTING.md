# Contributing

Issues and pull requests are welcome. This is a home-lab project maintained by
one person, so the useful contributions are the small, specific ones: a feed
that broke, a list that looks wrong, a parser that mishandles something.

## Before you open a pull request

1. **Run the tests.** They need no network and no keys:

   ```bash
   python3 -m unittest discover -s tests -v
   ```

   CI runs the same command before it publishes anything; a red suite blocks
   the nightly run, so a PR that breaks it is a PR that stops the feed.

2. **Do not commit generated data.** `Output/**` raw dumps, `malicious-*.txt`
   and `docs/index.html` are produced by the pipeline. If your change is to a
   generator, change the generator and let the next run regenerate the output.
   See [SIZE_FIX.md](SIZE_FIX.md) for why raw dumps stay out of git.

3. **Keep the guard honest.** Anything that can make the published lists
   smaller, emptier or less trustworthy must fail loudly rather than publish.
   That is the one rule this project will not trade away.

## Reporting a broken feed

Open an issue with the run date, the feed name and what the summary says
(`Output/YYYY/YYYY-MM/YYYYMMDD/daily_summary.md`). If the feed changed its
export URL or auth model, the collector prints the HTTP status it got — that
line is the most useful thing in the report.

## Reporting a bad indicator

An indicator that should not be in the lists is worth reporting: say which
list, the value, and where it came from. If a whole shared infrastructure
range is producing false positives, the right fix is usually an entry in
`infra_allow.txt` rather than an exception in code — see
[DOMAIN_FILTER.md](DOMAIN_FILTER.md).

## Style

- Python: standard library unless it is already in `requirements.txt`. A new
  dependency needs a reason in the PR description.
- Comments explain *why*, especially where a decision looks odd — most of the
  odd-looking code here is a scar from a specific failure.
- Shell: `set -o pipefail` in anything whose exit code is read by cron or CI.

## Security

Do not report vulnerabilities in a public issue — see [SECURITY.md](SECURITY.md).
