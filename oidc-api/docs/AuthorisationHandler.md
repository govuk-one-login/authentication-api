## Summary

Main entrypoint into One Login.

- Triggered by a call to /authorize from an RP

  - RP, who needs to be registered already in the client registry

- Possible journeys through lambda (link to page about journeys)
  - Auth journey (link to diagram)
  - Doc App journey (no auth UI associated) (link to diagram)

## Functionality

The lambda perform the following functions, although not all functions take place for every journey:

- Handling sessions (apply to module level in future)

  - See User session set or created - “parent session”
  - New client session - effectively a child of user session
  - Persistent session ID created if it doesn’t already exist
  - Redis / dynamoDB ?

- Validation

  - validates the client is in the client registry
  - Some things specific to individual RP, so it’s about the value itself, e.g. permitted vtr or scopes from client registry
  - Some things are general to all RPs for this lambda, mostly about the presence of particular params, e.g. must have a redirect_uri parameter

- Generates redirect response

  - What are the parameters
  - The auth params submitted here are converted to an encrypted jwt and will ‘follow’ an authentication flow potentially through many steps - in the first instance, they will be passed to auth frontend where they are mostly stored in the frontend session, but on their ‘way back’ they get stored in auth code and token store, and ultimately dictate what the userinfo response orch -> RP will contain
    Cookies in response
    Redirect URL ???

## Examples

### Input (for “normal” Auth journey) - will vary for other journeys:

```json
{
"queryStringParams": {
    "vtr" : ["Cl.Cm"],
    "scope" : "openid email phone",
    "claims" : {"userinfo":{"https://vocab.account.gov.uk/v1/passport":{"essential":true},"https://vocab.account.gov.uk/v1/coreIdentityJWT":{"essential":true},"https://vocab.account.gov.uk/v1/address":{"essential":true}}},
    "response_type":"code",
    "redirect_uri":"https://di-auth-stub-relying-party-build.london.cloudapps.digital/oidc/authorization-code/callback",
    "state":"XXXX",
    "prompt":"none",
    "nonce":"XXXX",
    "client_id":"XXXX",
    "ui_locales":"en"
},
   "Headers":""
}

```

More information about the data: (Link to data docs)

If needed sentence or 2 on important fields/ parameters

### Output

Redirect header:

```json
{
"Header": {
"Location" : "Https://gov.uk/one-login/sign-in-or-create"
},
"Body": ""
}
```
