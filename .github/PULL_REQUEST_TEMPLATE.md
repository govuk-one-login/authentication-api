## What?

Please include a summary of the change.

## Why?

Please include reason for the change and any other relevant context.

## Related PRs

Please include links to PRs in other repositories relevant to this PR.
Delete this section if not needed.


## Orchestration and Authentication mutual dependencies

Be careful when making changes to code in 'shared' components where each team has a copy.
Check with counterparts to see if changes need to be made in the other team's code.

In particular pay attention to classes representing Session data where changes need to be applied on both sides to avoid deserialization errors.

- [ ] Impact on orch and auth mutual dependencies has been checked.