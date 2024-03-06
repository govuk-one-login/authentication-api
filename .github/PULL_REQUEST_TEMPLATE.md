## What

<!-- Describe what you have changed and why -->

## How to review

<!-- Describe the steps required to review this PR.
For example:

1. Code Review
1. Deploy to sandpit with `./deploy-sandpit.sh -a`
1. Ensure that resources `x`, `y` and `z` were not changed
1. Visit [some url](https://some.sandpit.url/to/visit)
1. Log in
1. Ensure `x` message appears in a modal
-->

## 🚨⚠️ Orchestration and Authentication mutual dependencies ⚠️ 🚨

Be careful when making changes to code in 'shared' components where each team has a copy.
Check with counterparts to see if changes need to be made in the other team's code.

In particular pay attention to classes representing Session data where changes need to be applied on both sides to avoid deserialization errors.

- [ ] Impact on orch and auth mutual dependencies has been checked.

## Related PRs

<!-- Links to PRs in other repositories that are relevant to this PR.

This could be:
  - PRs that depend on this one
  - PRs this one depends on
  - If this work is being duplicated in other repos, other PRs
  - PRs which just provide context to this one.

Delete this section if not needed! -->
