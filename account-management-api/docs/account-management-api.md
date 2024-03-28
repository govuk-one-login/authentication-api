Status 16/05/2023

# Understand the account management API

The account management API is an internal interface used by the account management relying party (RP) to access the authentication database. It provides functionality to 

* authenticate a user
* update a user’s password or email address
* delete a user’s account 
* find out which multi-factor authentication (MFA) method a user selected
* change a user’s selected MFA method
* send a one-time passcode (OTP) notification to a user


## Accessing the account management API

The account management API is restricted to the account management RP using an API Gateway Lambda authoriser to control access.

To use the API, the account management RP needs to:

1. Get an access token from the /token endpoint - find more [information on how to request an access token](https://docs.sign-in.service.gov.uk/integrate-with-integration-environment/integrate-with-code-flow/#make-a-post-request-to-the-token-endpoint).
2. Include the access token in the header of the API request. 

This example shows how to include the access token in the header of the request: 
```
Authorization: Bearer <YOUR_ACCESS_TOKEN>
```

## Using the account management API

### Authenticate a user

You can make a `POST` request to the `/authenticate` endpoint to check that the user’s account exists and the password is valid. This is commonly used before a user changes their password or deletes their account.

Example request: 

```
POST /authenticate
{
 "email": "test@example.com",
 "password": "examplePassword"
}
```

Request Parameters:

| Parameter       | Required or optional | Description               |
|-----------------|----------------------|---------------------------|
| `email`         | Required             | The user's email address. |
| `password`      | Required             | The user's password.      |


If the request is successful, the account management API returns this response:
```
204 No Content
```

### Update a user’s password

You can make a `POST` request to the `/update-password` endpoint to change a user’s password.

If successful, GOV.UK Notify sends an email to the user's email address confirming that their password has changed.

Example request:
```
POST /update-password
{
 "email": "test@example.com",
 "newPassword": "newExamplePassword"
}
```

Request parameters: 

| Parameter       | Required or optional | Description               |
|-----------------|----------------------|---------------------------|
| `email`         | Required             | The user's email address. |
| `newPassword`   | Required             | The new password entered by the user. |


If the request is successful, the account management API returns this response:
```
204 No Content
```

### Update a user’s email address

You can update an existing user’s email address by using the `/update-email` endpoint and providing the new email address. 

Before updating a user’s email address, you must call the [`/send-otp-notification` endpoint](https://github.com/alphagov/di-authentication-api/edit/bau-draft-account-management-api-doc/account-management-api/docs/account-management-api.md#send-an-otp-notification-to-a-user) and include the `VERIFY_EMAIL` notification type to send an OTP to the user’s new email address.

If successful, GOV.UK Notify sends an email to the `existingEmailAddress` and `replacementEmailAddress` confirming that the user’s email address has changed.

Example request:
```
POST /update-email
{
 "existingEmailAddress": "test@example.com",
 "replacementEmailAddress": "test@newExample.com", 
  "otp": "123456"
}
```

Request parameters: 
| Parameter       | Required or optional | Description               |
|-----------------|----------------------|---------------------------|
| `existingEmailAddress`    | Required   | The user’s current email address. |
| `replacementEmailAddress` | Required   | The user’s new email address. |
| `otp`                     | Required   | The OTP that we sent to the user’s new email address and was entered by the user when requesting the update. |

If the request is successful, the account management API returns this response:
```
204 No Content
```

### Delete a user’s account

You can make a `POST` request to the `/delete-account` endpoint and delete a user’s account by providing the user’s email address.

If successful, GOV.UK Notify sends an email to the user’s email address confirming the deletion of the user’s account.

Example request:
```
POST /delete-account
{
 "email": "test@example.com"
}
```

Request parameters: 
| Parameter       | Required or optional | Description               |
|-----------------|----------------------|---------------------------|
| `email`         | Required             | The user's email address. |


If the request is successful, the account management API returns this response:
```
204 No Content
```

### Getting a user’s selected MFA method 

You can make a `POST` request to the `/mfa-method` endpoint to find out a user’s selected MFA method by providing the user’s email address.

The only 2 MFA methods available are to: 
* get an OPT sent by text message to your mobile phone 
* use an authenticator app 

Example request:
```
GET /mfa-method
{
 "email": "test@example.com"
}
```

Request parameters: 
| Parameter       | Required or optional | Description               |
|-----------------|----------------------|---------------------------|
| `email`         | Required             | The user's email address. |

Example response for a successful request: 
```
{
 "primaryMfaMethod": "AUTH_APP"
}
```

Response parameters:
| Parameter          | Description               |
|--------------------|---------------------------|
| `primaryMfaMethod` | The user’s primary MFA method when signing in to [GOV.UK One Login services at medium Cl.Cm protection level](https://docs.sign-in.service.gov.uk/integrate-with-integration-environment/choose-the-level-of-authentication/#choose-the-level-of-authentication-for-your-service). <br><br> The 2 available methods are: <ul><li>`AUTH_APP` for users wanting to use an authenticator app</li><li>`SMS` for users wanting to receive OTPs on their mobile phone</li></ul> |

### Update a user’s MFA method

You can make a `POST` request to the `/update-mfa-method` endpoint to change a user’s MFA method. 

When changing the MFA method from authenticator app to SMS, you must call the [`/send-otp-notification` endpoint](https://github.com/alphagov/di-authentication-api/edit/bau-draft-account-management-api-doc/account-management-api/docs/account-management-api.md#send-an-otp-notification-to-a-user) first to send an OTP to the user's mobile phone.

If successful,
* we remove the existing MFA method 
* GOV.UK Notify sends an email to the user’s email address confirming that their MFA method has changed

Example request:
```
POST /update-mfa-method
{
  "email": "test@example.com",
  "profileInformation": "07891234567",
  "mfaType": "SMS",
  "code": "123456"
}
```

Request parameters:
| Parameter              | Required or optional | Description               |
|------------------------|----------------------|---------------------------|
| `email`                | Required             | The user's email address. |
| `profileInformation`   | Required             | This is dependent on what mfaType is set to and must be one of the following: <br><br> <ul><li>phone number if `mfaType` is set to `SMS`</li><li>auth app secret if `mfaType` is set to `AUTH_APP`</li></ul> |
| `mfaType`              | Required             | The user’s new MFA method and must be set to one of the following: <br><br> <ul><li>`SMS`</li><li>`AUTH_APP`</li></ul> |
| `code`                 | Required             | The 6-digit OTP code entered by the user. |

If the request is successful, the account management API returns this response:
```
204 No Content
```

### Send an OTP notification to a user

To send an OTP in an email or text message, you must send a send notification lambda to the `/send-otp-notification` endpoint. The send notification lambda currently only supports 2 notification types: 

* `VERIFY_PHONE_NUMBER`
* `VERIFY_EMAIL`

You must provide a phone number when using the `VERIFY_PHONE_NUMBER` notification type.

Example request:
```
POST /send-otp-notification
{
  "email": "test@example.com",
  "notificationType": "VERIFY_PHONE_NUMBER",
  "phoneNumber": "07891234567"
}
```

Request parameters: 
| Parameter          | Required or optional | Description               |
|--------------------|----------------------|---------------------------|
| `email`            | Required             | The user's email address. |
| `notificationType` | Required             | The notification type used to decide where to send the 6-digit OTP to. It must be set to: <br><br><ul> <li>`VERIFY_PHONE_NUMBER` to send the code in an SMS to the user’s mobile `phoneNumber`</li> <li>`VERIFY_EMAIL` to send the code to the user’s `email` </li></ul> |
| `phoneNumber`      | Optional             | The phone number receiving the 6-digit OTP. This is only required when notificationType is `VERIFY_PHONE_NUMBER`. |

If the request is successful, the account management API returns this response:
```
204 No Content
```



