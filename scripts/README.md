# Scripts

## `report_stack_resources.sh` — CloudFormation stack resource report

Reports how many CloudFormation resources a stack uses and compares it against the
hard **500-resource-per-stack limit**. Useful for spotting which stacks (and which
endpoints) are approaching the limit.

It merges a stack's template directory the same way the deploy pipeline does
(`rain merge` over all `*.yaml`/`*.yml`), then prints three views:

1. **Totals** — authored count + estimated SAM-expanded count vs the 500 limit.
2. **By resource type** — count of each `AWS::*` type across the stack.
3. **By endpoint** — per source file (e.g. each `function/*.yaml`), with a per-type
   breakdown, so you can see the heaviest endpoints.

### Prerequisites

- [`rain`](https://github.com/aws-cloudformation/rain) on your `PATH`
  (only needed when the script does the merge itself — see `MERGED_TEMPLATE` below).
- Standard coreutils (`grep`, `awk`, `sed`, `find`) — already present on macOS/Linux.

### Usage

```bash
cd authentication-api

# Report the auth stack (stack name defaults to the dir basename)
./scripts/report_stack_resources.sh ci/cloudformation/auth

# Explicit stack name
./scripts/report_stack_resources.sh ci/cloudformation/auth auth

# Other stacks
./scripts/report_stack_resources.sh ci/cloudformation/account-management
./scripts/report_stack_resources.sh ci/cloudformation/account-data
./scripts/report_stack_resources.sh ci/cloudformation/utils
./scripts/report_stack_resources.sh ci/cloudformation/stubs
```

The full report prints to **stderr**; the script exits:

- `0` — OK (below the warn threshold)
- `0` with a `::warning::` — in the warn band (default 450–499)
- `1` with an `::error::` — estimated at/over the hard limit (500)

Capture just the report to a file:

```bash
./scripts/report_stack_resources.sh ci/cloudformation/auth 2> report.txt
```

### Options (environment variables)

| Var | Default | Purpose |
|---|---|---|
| `HARD_LIMIT` | `500` | CloudFormation resources-per-stack limit |
| `WARN_THRESHOLD` | `450` | Warn when the estimate is at/above this |
| `FAIL_ON_WARN` | `false` | If `true`, exit non-zero in the warn band |
| `MERGED_TEMPLATE` | _(unset)_ | Path to an already-merged template to reuse (skips `rain merge`, so `rain` is not required) |
| `GITHUB_STEP_SUMMARY` | _(set by GHA)_ | When set, a Markdown report is appended there |

Example — warn earlier and fail the command in the warn band:

```bash
WARN_THRESHOLD=400 FAIL_ON_WARN=true ./scripts/report_stack_resources.sh ci/cloudformation/auth
```

### CI

- **PR gate:** `.github/workflows/pre-merge-checks-sp.yml` runs the report for each
  stack after `sam validate`, reusing the already-merged template via
  `MERGED_TEMPLATE` (no second merge). Fails a PR only if a stack is estimated
  at/over the limit.
- **Trend tracking:** `.github/workflows/stack-resource-report.yml` runs on push to
  `main` (and `workflow_dispatch`) across all stacks, posting a Markdown summary.

### Notes / caveats

- The expanded total is an **estimate**: each `AWS::Serverless::Function` is counted
  `+2` (Version, Alias) and each `AWS::Serverless::Api` `+3` on top of the authored
  count. Actual deployed counts vary with which `Conditions` are active per
  environment (e.g. `IsSplunkEnabled`, `EnableProvisionedConcurrency`), so treat the
  number as a trend/guardrail signal rather than an exact deployed-resource count.
- `rain merge` normalises/de-dupes shared YAML anchors, so counts may differ slightly
  from a raw file concatenation.
