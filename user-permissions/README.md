# User Permissions

The User Permissions module provides a framework for managing user authentication permissions and tracking user actions within the GOV.UK One Login authentication service.

## Overview

This module implements a permission-based approach to authentication flows, allowing the system to:

1. Make decisions about whether users can proceed with specific authentication actions
2. Track user authentication attempts and actions
3. Implement temporary lockout mechanisms for security purposes

## Key Components

### UserPermissions Interface

The `UserPermissions` interface defines methods to check if a user is permitted to perform specific authentication actions:

- `canReceiveEmailAddress` - Check if a user can submit an email address
- `canSendEmailOtpNotification` - Check if the system can send an email OTP to the user
- `canVerifyEmailOtp` - Check if a user can verify an email OTP
- `canSubmitPassword` - Check if a user can submit a password
- `canSendSmsOtpNotification` - Check if the system can send an SMS OTP
- `canVerifySmsOtp` - Check if a user can verify an SMS OTP
- `canVerifyAuthAppOtp` - Check if a user can verify an authenticator app OTP

Each method returns a `Result<DecisionError, Decision>` which can be either:
- A `Decision.Permitted` with an attempt count
- A `Decision.TemporarilyLockedOut` with a reason, attempt count, and lockout duration

### UserActions Interface

The `UserActions` interface defines methods to track user authentication actions:

- Actions for email verification (correct/incorrect submissions)
- Actions for password verification (correct/incorrect submissions)
- Actions for SMS OTP verification (correct/incorrect submissions)
- Actions for authenticator app verification (correct/incorrect submissions)

### Supporting Entities

- `UserPermissionContext` - Contains user context information for permission decisions
- `Decision` - Sealed interface representing permission decisions (Permitted or TemporarilyLockedOut)
- `ForbiddenReason` - Enum of reasons why a user might be temporarily locked out
- `TrackingError` - Error types for action tracking
- `DecisionError` - Error types for permission decisions

## Usage Example

The module includes an `ExampleSmsVerificationHandler` that demonstrates how to use the interfaces:

1. Create a `UserPermissionContext` with user information
2. Check if the user is permitted to verify an SMS OTP
3. Handle temporary lockouts if applicable
4. Track incorrect/correct OTP submissions
5. Return appropriate responses

```java
// Check if user can verify SMS OTP
var checkResult = userPermissions.canVerifySmsOtp(journeyType, userPermissionContext);
if (checkResult.isFailure()) {
    return errorResponse;
}

var decision = checkResult.getSuccess();
if (decision instanceof Decision.TemporarilyLockedOut lockedOut) {
    // Handle lockout scenario
    return lockedOutResponse;
}

if (!isOtpValid(submittedOtp)) {
    // Track incorrect submission
    userActions.incorrectSmsOtpReceived(journeyType, userPermissionContext);
    return incorrectOtpResponse;
}

// Track correct submission
userActions.correctSmsOtpReceived(journeyType, userPermissionContext);
return successResponse;
```

## Implementation

To use this module, implement the `UserPermissions` and `UserActions` interfaces with your specific business logic for:

1. Rate limiting and lockout policies
2. Tracking authentication attempts
3. Storing and retrieving user permission state

The interfaces are designed to be flexible and can be implemented with various storage backends and security policies.