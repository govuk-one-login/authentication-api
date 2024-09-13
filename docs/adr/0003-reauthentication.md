# Decisions made for re-authentication -- DRAFT

Domain Language

Interactive login, front door log in

Business Rules

1. Interactive login, where the User provides at minimum a password, clears re-authentication error counts.
2. When a User is locked out of re-authenticating they can still login interactively.
3. A User will be locked out of re-authenticating if they enter any individual credential incorrectly more than 5 times.
4. A User is locked out of re-authenticating for 2 hours.
5. Silent login does not reset any error counts, including re-authentication.
6. A User can re-authenticate when their OneLogin session has expired.
7. A USer can re-authenticate if they have logged out of OneLogin.
8. Re-authenticating with multiple RPs in the same browser is not supported.
9. Error counts will be unique to an RP if the OneLogin session has expired or the User has logged out.
10. A User can re-authenticate without 2FA.
11. Error counts accrued without a OneLogin session are not cleared when the User completes an interactive login.
12. the reason we started capturing the counters separately is to enable fraud team with most possible detailed information about their incorrect credentials attempt.
13. No overall count. And an overall count so that they can't have 5 incorrect email entries and then 5 incorrect password entries and then 5 incorrect security code entries and still complete reauth.
14. If the RP requests for re-auth within 1hr after original sign-in, then other RPs will receive back channel logout. if the re-auth requests comes after 1hr, onelogin session for the user would have expired. so we will not trigger backchannel logout
15. A User that is locked out from changing their password can still re-authenticate

Other points clarify:

- LOP
- Ci.Cl
- Browser back button
- State machine was not changed, does it need a review?
