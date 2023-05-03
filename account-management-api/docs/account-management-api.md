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

<table class="tg">
<thead>
  <tr>
    <th class="tg-ktyi"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#000;background-color:transparent">Request Parameter</span></th>
    <th class="tg-ktyi"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#000;background-color:transparent">Required or optional</span></th>
    <th class="tg-ktyi"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#000;background-color:transparent">Description</span></th>
  </tr>
</thead>
<tbody>
  <tr>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">email</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">Required</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">The email address of the user.</span></td>
  </tr>
  <tr>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">password</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">Required</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">The current password of the user.</span></td>
  </tr>
</tbody>
</table>

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

<table class="tg">
<thead>
  <tr>
    <th class="tg-ktyi"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#000;background-color:transparent">Request Parameter</span></th>
    <th class="tg-ktyi"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#000;background-color:transparent">Required or optional</span></th>
    <th class="tg-ktyi"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#000;background-color:transparent">Description</span></th>
  </tr>
</thead>
<tbody>
  <tr>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">email</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">Required</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">The email address of the user.</span></td>
  </tr>
  <tr>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">password</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">Required</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">The new password entered by the user.</span></td>
  </tr>
</tbody>
</table>

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

<table class="tg">
<thead>
  <tr>
    <th class="tg-ktyi"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#000;background-color:transparent">Request Parameter</span></th>
    <th class="tg-ktyi"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#000;background-color:transparent">Required or optional</span></th>
    <th class="tg-ktyi"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#000;background-color:transparent">Description</span></th>
  </tr>
</thead>
<tbody>
  <tr>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">existingEmailAddress</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">Required</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">The current email address of the user.</span></td>
  </tr>
  <tr>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">replacementEmailAddress</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">Required</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">The new email address for the user.</span></td>
  </tr>
  <tr>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">otp</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">Required</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">The OTP entered by the user. This will be the OTP sent to the new email address.</span></td>
  </tr>
</tbody>
</table>

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

<table class="tg">
<thead>
  <tr>
    <th class="tg-ktyi"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#000;background-color:transparent">Request Parameter</span></th>
    <th class="tg-ktyi"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#000;background-color:transparent">Required or optional</span></th>
    <th class="tg-ktyi"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#000;background-color:transparent">Description</span></th>
  </tr>
</thead>
<tbody>
  <tr>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">email</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">Required</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">The email address of the user to be deleted.</span></td>
  </tr>
</tbody>
</table>

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
<table class="tg">
<thead>
  <tr>
    <th class="tg-ktyi"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#000;background-color:transparent">Request Parameter</span></th>
    <th class="tg-ktyi"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#000;background-color:transparent">Description</span></th>
  </tr>
</thead>
<tbody>
  <tr>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">email</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">The email address of the user.</span></td>
  </tr>
</tbody>
</table>

```json
{
 "email": ""
}
```

#### Example of a successful response
<table class="tg">
<thead>
  <tr>
    <th class="tg-ktyi"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#000;background-color:transparent">Response Parameter</span></th>
    <th class="tg-ktyi"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#000;background-color:transparent">Description</span></th>
  </tr>
</thead>
<tbody>
  <tr>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">primaryMfaMethod</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">The primary MFA method used by the user when signing in to GOV.UK One Login medium level services. This can be AUTH_APP or SMS.</span></td>
  </tr>
</tbody>
</table>

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

<table class="tg">
<thead>
  <tr>
    <th class="tg-ktyi"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#000;background-color:transparent">Request Parameter</span></th>
    <th class="tg-ktyi"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#000;background-color:transparent">Required or optional</span></th>
    <th class="tg-ktyi"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#000;background-color:transparent">Description</span></th>
  </tr>
</thead>
<tbody>
  <tr>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">email</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">Required</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">The email address of the user.</span></td>
  </tr>
  <tr>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">profileInformation</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">Required</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">When <span style="font-weight:400;font-style:normal;text-decoration:none;color:#A71D5D;background-color:#F5F5F5">mfaType</span> is SMS this will the phone number and when <span style="font-weight:400;font-style:normal;text-decoration:none;color:#A71D5D;background-color:#F5F5F5">mfaType</span> is AUTH_APP this will be the Auth App Secret.</span></td>
  </tr>
  <tr>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">mfaType</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">Required</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">The users new MFA Method. This can be either SMS or AUTH_APP</span></td>
  </tr>
  <tr>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">code</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">Required</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">The 6 digit OTP code entered by the user.</span></td>
  </tr>
</tbody>
</table>

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

<table class="tg">
<thead>
  <tr>
    <th class="tg-ktyi"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#000;background-color:transparent">Request Parameter</span></th>
    <th class="tg-ktyi"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#000;background-color:transparent">Required or optional</span></th>
    <th class="tg-ktyi"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#000;background-color:transparent">Description</span></th>
  </tr>
</thead>
<tbody>
  <tr>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">email</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">Required</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">The email address of the user.</span></td>
  </tr>
  <tr>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">notificationType</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">Required</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">Determines whether to send a 6 digit OTP to an email address using VERIFY_EMAIL or to send an SMS to a Mobile Phone Number using VERIFY_PHONE_NUMBER</span></td>
  </tr>
  <tr>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">phoneNumber</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">Optional</span></td>
    <td class="tg-n81y"><span style="font-weight:400;font-style:normal;text-decoration:none;color:#0B0C0C;background-color:transparent">The Mobile Phone Number where to send the user a 6 digit OTP. This is only required when <span style="font-weight:400;font-style:normal;text-decoration:none;color:#A71D5D;background-color:#F5F5F5">notificationType</span> is VERIFY_PHONE_NUMBER.</span></td>
  </tr>
</tbody>
</table>

```json
{
  "email": "",
  "notificationType": "",
  "phoneNumber": ""
}
```

#### Example of a successful response
```
204 No Content
```
