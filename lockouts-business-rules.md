# Business Rules & Logic for Lockouts

## Overview

There are 4 key scenarios that are of high priority and are treated as an MVP for what GOV.UK One Login's business rules should be, that are also being driven by a HMRC requirement.

Specifically HMRC have a requirement whereby they would like to increase the lock out period from 15 minutes to 2 hours.

### The 4 Key Scenarios

1. Create account
2. Sign in
3. Password reset
4. 2FA Account recovery

### Important Note on Lockouts

When we talk about 'lockouts' this does not mean the GOV.UK One Login as a whole is locked. It means the user is locked out from doing the step they were on when they triggered the lockout.

**Examples:**
- If a user is signing in, and enters the wrong password 6 times, they won't be able to enter their password for 2 hours.
- If a user has gone down the password reset journey, and enters the wrong email code 6 times, they won't be locked out from entering a password should they suddenly remember it, they will just be locked out from being able to request another email code on the password reset journey.

## What is Time To Live (TTL)?

In addition to the lockout rules, there's a Time To Live (TTL) feature that governs the duration during which a user's sign-in attempts remain valid before triggering a lockout. 

**Current TTL Settings:**
- Standard TTL: 15 minutes
- Sign in journey password entry: 2 hours

With the current TTL of 15 minutes, a user has that time window to attempt signing in, with a maximum of 6 password attempts. If they make 5 incorrect attempts within this 15-minute TTL period, they can simply wait until the time elapses. Once the TTL expires, they regain the ability to attempt signing in with another 6 attempts. 

**Security Vulnerability:** This setup presents a vulnerability, as users can exploit the timer reset to evade the lockout consequences. It is also worth noting that this feature is not public knowledge and so a user would not know that there is a timer that restarts.

## Count TTL vs OTP TTL

### OTP TTL
Time to live for the OTP code, indicating how long the code is available to the user until it expires.

### Count TTL
Time to live for the number of unsuccessful attempts a user has to enter the OTP. If the count expires, the user gets another round of attempts to enter the OTP again.

## Importance of Alignment

The goal is to ensure that the Count TTL and OTP TTL are aligned. This alignment ensures that both the OTP validity period and the number of attempts reset at the same time, preventing exploitation.

### Example Scenario: Misaligned TTLs

**Configuration:**
- OTP TTL: 1 hour
- Count TTL: 15 minutes
- 6 attempts before lockout

In this scenario, the code is valid for 1 hour, and the user has up to 5 attempts to enter the OTP within each 15-minute window. After 15 minutes, the count resets, giving the user another 5 attempts.

### Exploitation of Misalignment

A savvy user could exploit this misalignment by:

1. Entering 5 incorrect OTP attempts within the first 15 minutes
2. Waiting for the count to reset after 15 minutes
3. Repeating this process every 15 minutes for as long as the OTP code is valid (in this instance 1 hour)

By doing this, the user could effectively gain up to 20 attempts within the 1-hour validity period of the OTP, significantly increasing the chances of brute-forcing the correct OTP.

### Solution: Aligned TTLs

By aligning the Count TTL with the OTP TTL, both the OTP code and the count reset simultaneously. 

**Example:**
- OTP TTL: 15 minutes
- Count TTL: 15 minutes

This way, a user cannot wait for the count to reset and try more attempts, as the OTP code would have expired at the same time.

## Create Account Journey

| Action | Current Business Rule | Updated Business Rule | Date Modified | HMRC Requirement | Lockout | Security Rationale | OTP TTL | Count TTL |
|--------|----------------------|----------------------|---------------|------------------|---------|-------------------|---------|-----------|
| **Enter incorrect SMS code 6x** | The user has 5 attempts to enter the code correctly. The 6th incorrect attempt = locked out for 15 minutes | No change from the as-is | N/A | Y - 15 min | It could be used to send messages to another mobile number - spam - reputational damage, but easier to do it through create. Each OTP should only allow 5 attempts to get the correct value before a new OTP needs to be issued. This is to prevent brute force attacks. The number of OTP requested needs to be limited. | 15 minutes | 15 minutes |
| **Enter incorrect email code 6x** | User has 5 attempts to enter the code. After 6th incorrect attempt, they must get a new code and try again. No lockout is applied. | No change from the as-is | N/A | N | | 1 hour | 1 hour |
| **Enter incorrect Auth app** | The user has unlimited attempts at entering the OTP | No change from the as-is | N/A | N | Not sure on security risk. Each OTP should only allow 5 attempts to get the correct value before a new OTP needs to be issued. This is to prevent brute force attacks. The number of OTP requested needs to be limited. | 120 seconds* | 15 minutes |

*Note: The 120 seconds appears to be a specific timeout for Auth app OTP codes.

## Sign In Journey

| Action | Current Business Rule | Updated Business Rule | Date Modified | HMRC Requirement | Lockout | Security Rationale | OTP TTL | Count TTL |
|--------|----------------------|----------------------|---------------|------------------|---------|-------------------|---------|-----------|
| **Enter incorrect password 6x** | The user has 5 attempts to enter the password correctly. The 6th incorrect attempt = locked out for 15 minutes | The user has 5 attempts to enter the password correctly. The 6th incorrect attempt = locked out for 2 hours | | Y - 2 hours | Password is the most sensitive credential and should have the longest lockout period to prevent brute force attacks | 2 hours | 2 hours |
| **Enter incorrect SMS code 6x** | The user has 5 attempts to enter the code correctly. The 6th incorrect attempt = locked out for 15 minutes | The user has 5 attempts to enter the code correctly. The 6th incorrect attempt = locked out for 2 hours | | Y - 2 hours | It could be used to send messages to another mobile number - spam - reputational damage. Each OTP should only allow 5 attempts to get the correct value before a new OTP needs to be issued. This is to prevent brute force attacks. | 15 minutes | 15 minutes |
| **Enter incorrect email code 6x** | User has 5 attempts to enter the code. After 6th incorrect attempt, they must get a new code and try again. No lockout is applied. | User has 5 attempts to enter the code. After 6th incorrect attempt = locked out for 2 hours | | Y - 2 hours | | 15 minutes | 15 minutes |
| **Enter incorrect Auth app** | The user has unlimited attempts at entering the OTP | The user has 5 attempts to enter the OTP correctly. The 6th incorrect attempt = locked out for 2 hours | | Y - 2 hours | Each OTP should only allow 5 attempts to get the correct value before a new OTP needs to be issued. This is to prevent brute force attacks. | 120 seconds* | 120 seconds* |

## Password Reset Journey

| Action | Current Business Rule | Updated Business Rule | Date Modified | HMRC Requirement | Lockout | Security Rationale | OTP TTL | Count TTL |
|--------|----------------------|----------------------|---------------|------------------|---------|-------------------|---------|-----------|
| **Enter incorrect email code 6x** | User has 5 attempts to enter the code. After 6th incorrect attempt, they must get a new code and try again. No lockout is applied. | User has 5 attempts to enter the code. After 6th incorrect attempt = locked out for 2 hours | | Y - 2 hours | | 15 minutes | 15 minutes |
| **Enter incorrect SMS code 6x** | The user has 5 attempts to enter the code correctly. The 6th incorrect attempt = locked out for 15 minutes | The user has 5 attempts to enter the code correctly. The 6th incorrect attempt = locked out for 2 hours | | Y - 2 hours | It could be used to send messages to another mobile number - spam - reputational damage. Each OTP should only allow 5 attempts to get the correct value before a new OTP needs to be issued. This is to prevent brute force attacks. | 15 minutes | 15 minutes |

## 2FA Account Recovery Journey

| Action | Current Business Rule | Updated Business Rule | Date Modified | HMRC Requirement | Lockout | Security Rationale | OTP TTL | Count TTL |
|--------|----------------------|----------------------|---------------|------------------|---------|-------------------|---------|-----------|
| **Enter incorrect email code 6x** | User has 5 attempts to enter the code. After 6th incorrect attempt, they must get a new code and try again. No lockout is applied. | User has 5 attempts to enter the code. After 6th incorrect attempt = locked out for 2 hours | | Y - 2 hours | | 15 minutes | 15 minutes |
| **Enter incorrect SMS code 6x** | The user has 5 attempts to enter the code correctly. The 6th incorrect attempt = locked out for 15 minutes | The user has 5 attempts to enter the code correctly. The 6th incorrect attempt = locked out for 2 hours | | Y - 2 hours | It could be used to send messages to another mobile number - spam - reputational damage. Each OTP should only allow 5 attempts to get the correct value before a new OTP needs to be issued. This is to prevent brute force attacks. | 15 minutes | 15 minutes |

## Key Changes Summary

The main changes being implemented are:

1. **Lockout Period Extension**: Increasing lockout periods from 15 minutes to 2 hours for most scenarios to meet HMRC requirements
2. **TTL Alignment**: Ensuring Count TTL and OTP TTL are aligned to prevent exploitation
3. **Consistent Security**: Applying consistent security measures across all authentication journeys
4. **Brute Force Prevention**: Limiting attempts and implementing appropriate lockout periods to prevent brute force attacks

## Security Considerations

- **Password Protection**: Password entry has the longest lockout period as it's the most sensitive credential
- **SMS Spam Prevention**: SMS lockouts help prevent abuse for sending spam messages to other numbers
- **Brute Force Mitigation**: Limited attempts with appropriate lockouts prevent systematic attacks
- **TTL Synchronization**: Aligned TTLs prevent users from exploiting timing differences to gain additional attempts
