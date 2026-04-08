## Summary

Main entrypoint into One Login.

- Triggered by a call to /authorize from an RP

  - RP must already be in the client registry

- Possible journeys through lambda (can be found in [orchestration diagrams](../../docs/diagrams/orchestration))
  - [Auth journey](../../docs/diagrams/orchestration/auth-only)
  - [Doc App journey](../../docs/diagrams/orchestration/auth-only)

## Functionality

The lambda performs the following functions, although not all functions take place for every journey:

- Handling sessions

  - User session set or created - “parent session”
  - New client session - effectively a child of user session
  - Persistent session ID created if it doesn’t already exist
  - All stored in dynamo

- Validation

  - Validates the client is in the client registry
  - Some things specific to individual RP, so it’s about the value itself, e.g. permitted vtr or scopes from client registry
  - Some things are general to all RPs for this lambda, mostly about the presence of particular params, e.g. must have a redirect_uri parameter

- Generates redirect response

  - Location header will determine where the browser should redirect to. In a success case the redirect url will be an oauth compliant authorize request.
  - The auth params submitted here are converted to an encrypted jwt and will ‘follow’ an authentication flow potentially through many steps - in the first instance, they will be passed to auth frontend where they are mostly stored in the frontend session, but on their ‘way back’ they get stored in auth code and token store, and ultimately dictate what the userinfo response orch -> RP 
  - Will contain Cookies in response

## Examples

### Input (for “normal” Auth journey) - will vary for other journeys:

```json
{
"queryStringParams": {
  "vtr": ["Cl"],
  "scope": "openid email phone",
  "claims": {"userinfo":{"https:\/\/vocab.account.gov.uk\/v1\/passport":{"essential":true},"https:\/\/vocab.account.gov.uk\/v1\/coreIdentityJWT":{"essential":true},"https:\/\/vocab.account.gov.uk\/v1\/address":{"essential":true}}},
  "response_type": "code",
  "redirect_uri": "https://rp.stubs.account.gov.uk/oidc/authorization-code/callback",
  "state": "D9fDA1Y_s8WwjJ2NOA_UDKY0wpV53NFNG4k8bLkyKDM",
  "prompt": "none",
  "nonce": "ZVOt6pvwZZDQzboS7Rzrd_16vZ"
},
   "Headers": {
     "Cookie": "cookies_preferences_set=%7B%22analytics%22%3Atrue%7D; _gid=GA1.3.1277859721.1697125152; _ga=GA1.3.944961392.1697125152; _ga_MHX9DPZ660=GS1.1.1697125152.1.1.1697125162.0.0.0; di-persistent-session-id=bku1qcOpFmDQ3oW94eiGfVoRb8E; lng=en; gs=DhWsc2kZoyZT738J2FVH0WGd0hM.U4_I1ze1dAGWMSe36v3CnATn1X4; _gat_UA-26179049-1=1"
   }
}

```

This [page](https://docs.sign-in.service.gov.uk/integrate-with-integration-environment/integrate-with-code-flow/#create-a-url-encoded-json-object-for-lt-claims-request-gt) has more information about the data

### Output

Redirect header:

```
HTTP/2 302
Location: https://signin.account.gov.uk/authorize?<Params>
Set-Cookie: di-persistent-session-id=bku1qcOpFmDQ3oW94eiGfVoRb8E; Max-Age=34190000; Domain=account.gov.uk; Secure; HttpOnly;
Set-Cookie: gs=H-ECWqA-fBnM9NxCMmuAd1ceDqM.2eklz3pDfcYKqoDw2_Tb2PXsEPA; Max-Age=3600; Domain=account.gov.uk; Secure; HttpOnly;
```
