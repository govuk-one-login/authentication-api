# Account Management API

Date: 2023-05-03

## Context

API overview of the Account Management API.

## Authorization
Access of the Account Management API is restricted to the Account Management RP. Authentication to the Account Management API is handled via an API Gateway Lambda Authorizer. The Account Management Client sends the Access token it received from the Orchestration `/token` endpoint in the Authorization header. The Authorizer will perform validation such as checking the signature of the token and checking that the Scopes contain the custom `am` scope.
```
Authorization: Bearer <access-token>
```
 
## Endpoints

### Authenticate the user
Checks that the account exists and the password is valid. This is used in circumstances such as prior to users updating their password.
#### Example request
```
POST /authenticate
```
```json
{
 "email": "",
 "password": ""
}
```

#### Example of a successful response

```
204 No Content
```


### Update the users password
This will update the user's password with the new password provided. 

If successful, an email will be sent to the users email address that their password has changed.
#### Example request
```
POST /update-password
```
```json
{
 "email": "",
 "newPassword": ""
}
```
#### Example of a successful response
```
204 No Content
```


### Update the users email address
This will update the existing users email address with the replacement email address provided. You will need to ensure that the `/send-otp-notification` endpoint is called first with the `VERIFY_EMAIL` notification type so that an OTP is sent to the users new email address. 

If successful, an email will be sent to the users old AND new email address that their email address has changed.  

#### Example request
```
POST /update-email
```
```json
{
 "existingEmailAddress": "",
 "replacementEmailAddress": "", 
  "otp": ""
}
```
#### Example of a successful response
```
204 No Content
```


### Delete the users account
This will delete the account for the email provided in the request. 

If successful, an email will be sent to the users email address that their account has been deleted.
#### Example request
```
POST /delete-account
```
```json
{
 "email": ""
}
```

#### Example of a successful response
```
204 No Content
```


### Retrieve the users MFA method
This will retrieve the users primary MFA method. 
#### Example request
```
GET /mfa-method
```
```json
{
 "email": ""
}
```

#### Example of a successful response
The response will contain either `SMS` or `AUTH_APP`
```json
{
 "primaryMfaMethod": "AUTH_APP"
}
```


### Update the users MFA method
This is used to update the users primary MFA method. Bear in mind that this will remove the users existing MFA method, if the code sent in the request is valid. When updating to `SMS`, you will need to ensure that the `/send-otp-notification` endpoint is called first so that an OTP is sent to the users mobile phone. 

If successful, an email will be sent to the users email address that their MFA method has changed.
#### Example request
```
POST /update-mfa-method
```
```json
{
  "email": "", 
  "profileInformation": "",
  "mfaType": "",
  "code": ""
}
```
#### Example of a successful response
```
204 No Content
```


### Send a OTP notification to the user
If you need to send an OTP in an email or text message, you can use the send notification lambda. It currently only supports 2 notification types `VERIFY_PHONE_NUMBER` and `VERIFY_EMAIL`. Phone number is only required when using the `VERIFY_PHONE_NUMBER` notification type.  

#### Example request
```
POST /send-otp-notification
```
```json
{
  "email": "",
  "notificationType": "VERIFY_EMAIL", 
  "phoneNumber": ""
}
```

#### Example of a successful response
```
204 No Content
```
