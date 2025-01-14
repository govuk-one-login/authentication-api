#### _Authentication team template - delete as required_

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

## Checklist

<!-- 🚨⚠️ Orchestration and Authentication mutual dependencies ⚠️ 🚨

Be careful when making changes to code in 'shared' components where each team has a copy.
Check with counterparts to see if changes need to be made in the other team's code.

In particular pay attention to classes representing Session data where changes need to be applied on both sides to avoid deserialization errors.
-->

- [ ] Impact on orch and auth mutual dependencies has been checked.

<!-- Changes required to stub-orchestration?

If the contract between Orch and Auth has changed then this may need to be reflected in updates to [stub-orchestration](https://github.com/govuk-one-login/authentication-stubs/tree/main/orchestration-stub)

-->

- [ ] No changes required or changes have been made to stub-orchestration.

<!-- UCD Review
When a new feature or front-end change goes live, ensure that a review of it has been performed by UCD. The review may have already taken place, but it is important to check that it did before going live.

Think about if the change you are making here will enable a change UCD should review (i.e. toggling a feature flag).

Contact UCD colleagues in the Authentication team to identify the best way to approach the review.

Delete this item if this PR does not need a UCD review.
-->

- [ ] A UCD review has been performed.

## Related PRs

<!-- Links to PRs in other repositories that are relevant to this PR.

This could be:
  - PRs that depend on this one
  - PRs this one depends on
  - If this work is being duplicated in other repos, other PRs
  - PRs which just provide context to this one.

Delete this section if not needed! -->

---

#### _Orchestration team template - delete as required_

### Wider context of change

<!-- Short explanation of why this change is required and how it fits into larger initiatives. For example:

As part of the max age initiative, Orch need to return the auth_time claim in the ID token to RPs. This is so that RPs can compare max_age, auth_time and the current time, to determine if the ID token is valid.
-->

### What’s changed

<!-- What’s changed in this PR. For example:

The auth_time claim is retrieved from the auth code exchange data store, and then added to all token responses (not just when the RP includes max age in the authorize request). Implementation is feature flagged and enabled in all envs except production. As this change is RP facing, it needs to be tested in integration and RPs made aware of the changes before releasing to production.
-->

### Manual testing

<!-- Describe the manual testing completed. For example:

Deployed to Orch dev and observed the following succesful test cases:
- max age not set, sign in 2FA journey, claims returned
- max age not set, no sign in journey, claims returned
- max age 0 forces reauthentication
- max age 1234 does not force reauthentication
- max age 5 forces reauthentication
- max age -3 fails with appropriate error message
- max age “abc” fails with appropriate error message
-->

### Checklist

<!-- Be careful when making changes to code in 'shared' components where each team has a copy.
Check with counterparts to see if changes need to be made in the other team's code.
In particular pay attention to classes representing Session data where changes need to be applied on both sides to avoid deserialization errors.
-->

- [ ] Impact on orch and auth mutual dependencies has been checked.

<!-- Changes required to contract tests?
If there are changes to the API interaction between Orchestration and other services, the contract tests may need updating
-->

- [ ] Changes have been made to contract tests or not required.

<!-- Changes required to the simulator?
If there are RP facing changes then this may need to be reflected in updates to [simulator](https://github.com/govuk-one-login/simulator).
-->

- [ ] Changes have been made to the simulator or not required.

<!-- Changes required to the stubs?
eg. RP / IPV / SPOT / Auth stub
-->

- [ ] Changes have been made to stubs or not required.

<!-- Deployed to authdev?
If this is a session split change, please check that it can be deployed to either authdev1 or authdev2. See [slack](https://gds.slack.com/archives/C060UE8NSP4/p1733137845652609).
-->

- [ ] Successfully deployed to authdev or not required.

<!-- Run Authentication acceptance tests against sandpit?
As Orch code reaches production faster than Auth code, if this change could affect Auth, please run [Authentication acceptance tests](https://github.com/govuk-one-login/authentication-acceptance-tests) against sandpit.
-->

- [ ] Successfully run Authentication acceptance tests against sandpit or not required.

### Related PRs

<!-- Links to PRs in other repositories that are relevant to this PR.

This could be:
  - PRs that depend on this one
  - PRs this one depends on
  - If this work is being duplicated in other repos, other PRs
  - PRs which just provide context to this one.

Delete this section if not needed! -->
