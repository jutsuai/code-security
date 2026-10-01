# Jutsu Security scan

A reusable GitHub Actions workflow that scans a repository's changes for committed secrets
(Gitleaks 8.30.1) and for dependencies with known vulnerabilities (osv-scanner 2.6.0), and sends
the results to Jutsu. It runs on your runner. **No source code and no secret value leaves it.**

A repository uses it through `.github/workflows/jutsu-security.yml`, which Jutsu offers as a pull
request or as a file to add yourself:

```yaml
name: Jutsu Security
on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:
permissions: {}
jobs:
  jutsu:
    permissions:
      contents: read     # the scan reads the repository on the runner
      id-token: write    # the report proves which workflow produced it
    uses: jutsuai/code-security/.github/workflows/scan.yml@<40-character commit SHA>
```

It passes no secrets. Pin the commit SHA Jutsu gives you; Jutsu accepts reports only from the
releases it lists.

## What it does

The workflow has two jobs.

**scan** has `contents: read` and no identity token. It:

1. fetches the commits under review with the run's own read-only token, without checking out a
   working tree: `<merge base>..<head>` for a pull request, `<before>..<after>` for a push. A new
   branch, a manual run and a push that changes `jutsu-security.yml` also scan the current tree;
2. runs Gitleaks over those commits (merge commits included) with Jutsu's configuration. A
   repository's own `.gitleaks.toml`, `.gitleaksignore` and `gitleaks:allow` comments have no
   effect, so a change cannot switch off its own scan;
3. writes each lockfile (from the head and from the base) to a scratch directory and runs
   osv-scanner on it with an empty configuration and no dependency resolution. A vulnerability is
   *introduced* when the head has it and the base does not;
4. replaces each secret value with its SHA-256 digest, drops the value, and discards the tools'
   own output, so a secret a tool prints never reaches the run's log;
5. passes the result, identifiers only and compressed, to the report job.

It never installs, builds or runs anything from the repository. The two scanners are downloaded
from their GitHub releases and checked against pinned sha256 sums (`tools.json`) before they run.

**report** has `id-token: write` and no access to the repository. It asks GitHub for an identity
token for Jutsu's API, adds the run's own facts (event, pull request number, head and base, run id
and attempt), and sends the report, retrying for up to ten minutes. If the scan job failed, timed
out or was cancelled, it reports that instead.

Limits: at most 250 commits, 200 lockfiles, 20 MB per lockfile and 500 findings per tool. A change
over a limit is reported as incompletely scanned, never as clean.

## What it sends

This, and nothing else:

```
identity (from the report job's own context), by event:
  pull_request:      prNumber, ref = refs/pull/<prNumber>/merge, sha (the merge commit GitHub ran on),
                     headSha, baseRef, baseSha, runId, runAttempt
  push:              ref = refs/heads/<branch>, sha = after, before, after, headSha = after, runId, runAttempt
  workflow_dispatch: ref = refs/heads/<branch>, sha, headSha = sha, runId, runAttempt
scan (the scan job's output, passed through unchanged):
  scanResult: success | failure | cancelled | timed_out
  secrets: { coverage: complete|incomplete_input|failed, reason, tool: {name, version},
             findings: [{ ruleId, path, startLine, endLine, commitSha, valueDigest, inHeadTree }] }
  vulnerabilities: {
             coverage: { head: complete|incomplete_input|failed, base: complete|incomplete|none },
             reason: { head, base }, manifests: [{ side, path, status }], tool, queriedAt,
             findings: [{ advisoryIds[], ecosystem, package, version, manifestPath, introduced }] }
  commits: [sha]  (what the range scan covered, at most 250)
  inventory (default-branch runs): [{ ecosystem, package, version, manifestPath }]
  treeScanned: boolean
```

In words: file paths, line numbers, commit SHAs, package names and versions, advisory ids, rule
ids, and a SHA-256 digest of each secret. Jutsu re-keys each digest with a server-side key before
storing it. A digest of a short, guessable secret can be guessed; that is what lets Jutsu recognise
the same secret twice.

Package names and versions are also sent to [OSV](https://osv.dev) by osv-scanner, from your
runner.

## Pull requests from forks

A run for a pull request from a fork gets no identity token from GitHub, so it cannot send a
report, and its report job fails with that reason. Jutsu does not scan pull requests from forks.
