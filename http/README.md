# HTTP

## Client Registry API HTTP requests

The Client Registry API can be tested using the files in this folder. Duplicate the
`http-client.private.env.json.template` file and remove the `.template`. Set `sandpit-api-key` with the API key for the
sandpit client registry API that can be found in AWS, in the account sandpit deploys into.

The templates contain necessary fields, but if you want to test a new field add that to the JSON.

The public key and client id, if necessary, are also be set in `http-client.private.env.json`.

Run the HTTP requests by selecting `sandpit` in the `Run with` dropdown at the top of the file.

## AM API testing using curl

See https://govukverify.atlassian.net/wiki/spaces/LO/pages/4606132332/Manually+Testing+Account+Management+API

The proxy is only available in dev environments but as the access token can only be retrieved from the RP Stub only 
authdev3 can be used.  Otherwise AWS Cloudshell is available in all environments where you can get a token.

To retrieve an access token from the RP Stub select the 'Account Management' scope then sign in as normal.  Copy the 
access token to the clipboard and export it in the shell as below.  The token only lasts for 3 minutes so will need 
refreshing after that.  Stay signed-in and start the journey from the stub again which will trigger a silent loging and 
generate a new token.

It is difficult to transfer scripts over to AWS Cloudshell when run in a vpc which is why these commands are not in a 
script file.  Scripts can be transferred via an S3 bucket but this is to be avoided outside of dev environments.  Copy 
and paste works for limited scripts only as the copy operation breaks formatting badly.

### General Configuration 

Set these variables with the correct values in the shell

```
export BASE_URL="https://am.private.api.endpoint.or.proxy.host"
export AUTH_TOKEN="your-auth-access-token-here"
export EMAIL="your.email@digital.cabinet-office.gov.uk"
export PUBLIC_SUBJECT_ID="your-public-subject-id"
export MFA_IDENTIFIER="your-mfa-identifier"
```

### Account Management endpoint testing

#### authenticate

```
curl -X POST "$BASE_URL/authenticate" \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "email": "'$EMAIL'",
        "password": "'your-password'"
    }'
```

#### send-otp-notification

notificationType: VERIFY_EMAIL or VERIFY_PHONE_NUMBER
Call before 'update-email' with the new email to get an otp

```
curl -X POST "$BASE_URL/send-otp-notification" \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "notificationType": "'VERIFY_PHONE_NUMBER'",
        "email": "'$EMAIL'",
        "phoneNumber": "07xxxxxxxxx"
    }'
```

#### update-email

Call 'send-otp-notification' to get an otp

```
curl -X POST "$BASE_URL/update-email" \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "existingEmailAddress": "'$EMAIL'",
        "replacementEmailAddress": "new_email_registered.with_notify@digital.cabinet-office.gov.uk",
        "otp": "111111"
    }'
```

#### update-password

Requires client registry change

```
curl -X POST "$BASE_URL/update-password" \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "email": "'$EMAIL'",
        "newPassword": "'new_password'"
    }'
```


#### delete-account

Requires client registry change

```
curl -X POST "$BASE_URL/delete-account" \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "email": "'$EMAIL'"
    }'
```

#### update_phone_number

Requires client registry change

```
curl -X POST "$BASE_URL/update-phone-number" \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "email": "'$EMAIL'",
        "phoneNumber": "07xxxxxxxxx",
        "otp": "111111"
    }'
```

### Method Management endpoint testing

#### Retrieve mfa-methods

```
curl -X GET "$BASE_URL/v1/mfa-methods/$PUBLIC_SUBJECT_ID" \
    -H "Authorization: Bearer $AUTH_TOKEN"
```

#### Create SMS MFA method

Call 'send-otp-notification' to get an otp

```
curl -X POST "$BASE_URL/v1/mfa-methods/$PUBLIC_SUBJECT_ID" \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "mfaMethod": {
            "priorityIdentifier": "BACKUP",
            "method": {
                "mfaMethodType": "SMS",
                "phoneNumber": "07xxxxxxxxx",
                "otp": "111111"
            }
        }
    }'
```

#### Create Auth App MFA method

Call 'send-otp-notification' to get an otp

```
curl -X POST "$BASE_URL/v1/mfa-methods/$PUBLIC_SUBJECT_ID" \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "mfaMethod": {
            "priorityIdentifier": "BACKUP",
            "method": {
                "mfaMethodType": "AUTH_APP",
                "credential": "your-credential-here"
            }
        }
    }'
```

#### Update SMS MFA method

Call 'send-otp-notification' to get an otp

```
curl -X PUT "$BASE_URL/v1/mfa-methods/$PUBLIC_SUBJECT_ID/$MFA_IDENTIFIER" \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "mfaMethod": {
            "priorityIdentifier": "BACKUP",
            "method": {
                "mfaMethodType": "SMS",
                "phoneNumber": "07xxxxxxxxx",
                "otp": "111111"
            }
        }
    }'
```

#### Update Auth App MFA method

```
curl -X PUT "$BASE_URL/v1/mfa-methods/$PUBLIC_SUBJECT_ID/$MFA_IDENTIFIER" \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "mfaMethod": {
            "priorityIdentifier": "BACKUP",
            "method": {
                "mfaMethodType": "AUTH_APP",
                "credential": "your-credential-here"
            }
        }
    }'
```

#### Delete MFA method

```
curl -X DELETE "$BASE_URL/v1/mfa-methods/$PUBLIC_SUBJECT_ID/$MFA_IDENTIFIER" \
        -H "Authorization: Bearer $AUTH_TOKEN"
```