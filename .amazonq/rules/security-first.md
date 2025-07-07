# Security-First Development

Always prioritize security when writing code for this authentication system.

```java
// BAD - Insecure practices
String password = "hardcoded-secret";
log.info("User entered password: " + userPassword);
executeQuery("SELECT * FROM users WHERE id = " + userId);

// GOOD - Secure practices
String password = configurationService.getSecretFromSecureStore();
log.info("Password validation attempted for user: {}", userId);
executeQuery("SELECT * FROM users WHERE id = ?", userId);
```

Security requirements:
- Never hardcode secrets or credentials
- Use parameterized queries to prevent injection attacks
- Don't log sensitive information like passwords or tokens
- Keep dependencies updated to avoid known vulnerabilities
- Use secure random for generating tokens and IDs
- Validate all user inputs