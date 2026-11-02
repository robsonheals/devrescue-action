# DevRescue CI Health Check

Scores your GitHub Actions workflows from 0 to 100 and points at the exact line to change:

- **No dependency cache**: every run re-downloads `node_modules` from the registry.
- **No concurrency group on pull requests**: a new push doesn't cancel the outdated run.
- **No `timeout-minutes`**: a hung job runs for the 6-hour default.
- **CI on docs-only changes**, and a few other cheap wins.

Findings show up as annotations on the workflow file and in the job summary. Everything runs on the runner: no token, no network calls, nothing uploaded.

We ran the same checks on 139 popular JS/TS repositories: [only 1 passed all three basic checks](https://devrescue.vercel.app/research).

## Usage

```yaml
name: CI health
on:
  pull_request:
    paths: ['.github/workflows/**']
  workflow_dispatch:

permissions:
  contents: read

jobs:
  ci-health:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v7
      - uses: robsonheals/devrescue-action@v1
        with:
          min-score: 80   # optional: fail below 80. Default 0 never fails.
```

### Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Directory that contains `.github/workflows`. |
| `min-score` | `0` | Fail the job when the score is below this value. `0` never fails. |
| `annotations` | `true` | Annotate findings on the workflow files. `false` prints them to the log only. |

### Outputs

| Output | Description |
|---|---|
| `score` | CI health score, 0–100. Empty when there are no workflows. |
| `findings` | Number of findings. |

## What it deliberately doesn't flag

To keep false positives low:

- Release, publish and deploy workflows are not asked to cache (they often skip caches on purpose, against cache poisoning).
- Setup done in local composite actions or reusable workflows is skipped for the cache check.
- npm projects cached automatically by `actions/setup-node` v5+ (`packageManager` set to npm) count as cached.
- Concurrency is only expected on workflows that run on `pull_request`.

If you think a finding is wrong, [open an issue](https://github.com/robsonheals/devrescue-action/issues) with the workflow: that's the most useful feedback.

## How to fix each finding

- [Cache dependencies (npm, pnpm, yarn)](https://devrescue.vercel.app/guides/github-actions-cache-dependencies)
- [Cancel outdated PR runs with concurrency](https://devrescue.vercel.app/guides/cancel-redundant-github-actions-runs)
- [Set timeout-minutes](https://devrescue.vercel.app/guides/github-actions-timeout-minutes)

## Badge

Show the score in your README:

```md
[![CI health](https://devrescue.vercel.app/badge/OWNER/REPO)](https://devrescue.vercel.app/?repo=OWNER/REPO)
```

You can also run the check in the browser, without installing anything: [devrescue.vercel.app](https://devrescue.vercel.app).

## License

MIT
