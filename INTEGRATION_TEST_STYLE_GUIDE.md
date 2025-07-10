# Integration Test Style Guide

## Summary

This document establishes conventions for writing consistent, maintainable integration tests across the authentication API project.

Integration tests verify that our lambda handler classes integrate correctly with external resources such as AWS services, APIs and data stores. LocalStack is used to provide useful stubs of AWS services for testing purposes.

Unlike unit tests, integration tests should not mock any services they use. Instead, they should test how the lambda handler works in a realistic AWS environment, using actual service implementations or LocalStack equivalents. This approach ensures that integration points, configuration, and service interactions are properly validated. Logging should be treated as a first-class feature in integration tests, with proper verification of audit events, metrics, and structured logging output to ensure observability requirements are met in production.

### Blueprint

```java
// Class naming follows convention (see Naming Standards)
class UserRegistrationHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    
    // Test constants with descriptive ALL_CAPS naming (see Class Structure > Test Constants)
    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_PASSWORD = "test-password";
    private static final String TEST_PHONE_NUMBER = "+447700900000";
    
    // Static test data objects (see Class Structure > Static Test Data)
    private static final UserProfile TEST_USER_PROFILE = UserProfile.builder()
            .email(TEST_EMAIL)
            .password(TEST_PASSWORD)
            .build();
    
    @BeforeEach
    void setUp() { // Descriptive setup method name (see JUnit Annotations > @BeforeEach Setup)
        handler = new UserRegistrationHandler(CONFIGURATION_SERVICE);
        // Clear queues for test isolation (see Best Practices)
        notificationsQueue.clear();
        txmaAuditQueue.clear();
    }
    
    @AfterEach
    void tearDown() { // Cleanup after each test for isolation (see Best Practices > Isolation)
        // Clear queues to prevent test interference
        notificationsQueue.clear();
        txmaAuditQueue.clear();
        // Clean up any test data if needed
        userStore.deleteUser(TEST_EMAIL);
    }
    
    @Nested
    class SuccessfulRegistration { // Nested class for grouping (see JUnit Annotations > @Nested Classes)
        
        @DisplayName("User successfully registers with valid email and password")
        @Test
        void aUserSuccessfullyRegistersWithValidCredentials() { // User action naming style (see Naming Standards)
            
            // GIVEN (setup) - Clear test structure (see Test Structure > Given-When-Then Pattern)
            var requestBody = constructRegistrationRequest(TEST_EMAIL, TEST_PASSWORD);
            Map<String, String> headers = Map.of("Content-Type", "application/json");
            
            // WHEN (action)
            var response = makeRequest( // Base class method usage (see Class Structure > Base Class Extension)
                    Optional.of(requestBody),
                    headers,
                    Collections.emptyMap());
            
            // THEN (assertions)
            assertEquals(201, response.getStatusCode(), "Expected successful registration"); // Descriptive assertion messages (see Assertions > Response Assertions)
            
            // Verify state changes (see Assertions > State Assertions)
            var userProfile = userStore.getUserProfileFromEmail(TEST_EMAIL);
            assertTrue(userProfile.isPresent(), "User should be created in store");
            
            // Verify side effects - notifications (see Best Practices > Verification)
            assertNotificationsReceived(
                    notificationsQueue,
                    List.of(new NotifyRequest(TEST_EMAIL, REGISTRATION_CONFIRMATION)));
            
            // Verify audit events using helper pattern (see Helper Methods and Classes > AuditEventExpectation Pattern)
            verifyAuditEvents(
                    List.of(USER_REGISTRATION_COMPLETED),
                    Map.of(USER_REGISTRATION_COMPLETED.name(), 
                           Map.of("extensions.journey_type", "REGISTRATION")));
        }
    }
    
    @Nested
    class ErrorCases { // Error scenarios grouped separately (see JUnit Annotations > @Nested Classes)
        
        @Test
        void shouldReturn400WhenEmailIsInvalid() { // Technical naming style for errors (see Naming Standards)
            
            // GIVEN
            var requestBody = constructRegistrationRequest("invalid-email", TEST_PASSWORD);
            
            // WHEN
            var response = makeRequest(Optional.of(requestBody), Collections.emptyMap(), Collections.emptyMap());
            
            // THEN
            assertEquals(400, response.getStatusCode()); // Status code assertion first (see Assertions > Response Assertions)
            assertThat(response, hasJsonBody(ErrorResponse.ERROR_1004)); // Custom matcher usage (see Assertions > Response Assertions)
        }
    }
    
    // Helper method with descriptive name (see Helper Methods and Classes > Setup Helper Methods)
    private String constructRegistrationRequest(String email, String password) {
        return format( // String.format usage (see Helper Methods and Classes > Request Construction)
                """
                {
                  "email": "%s",
                  "password": "%s"
                }
                """, email, password); // Text blocks for JSON (see Helper Methods and Classes > Request Construction)
    }
    
    // Audit verification helper (see Helper Methods and Classes > AuditEventExpectation Pattern)
    private void verifyAuditEvents(
            List<AuditableEvent> expectedEvents,
            Map<String, Map<String, String>> eventExpectations) {
        
        List<String> receivedEvents = assertTxmaAuditEventsReceived(txmaAuditQueue, expectedEvents);
        
        for (Map.Entry<String, Map<String, String>> eventEntry : eventExpectations.entrySet()) {
            AuditEventExpectation expectation = new AuditEventExpectation(eventEntry.getKey());
            
            for (Map.Entry<String, String> attributeEntry : eventEntry.getValue().entrySet()) {
                expectation.withAttribute(attributeEntry.getKey(), attributeEntry.getValue());
            }
            
            expectation.verify(receivedEvents);
        }
    }
}
```

## Best Practices

1. **Consistency**: Follow the same patterns across all integration tests
2. **Readability**: Use descriptive names and clear test structure
3. **Maintainability**: Create reusable helper methods and test data
4. **Isolation**: Each test should be independent and clean up after itself
5. **Verification**: Assert both positive outcomes and side effects (audit events, notifications)
6. **Error Coverage**: Test both success and failure scenarios comprehensively

## Naming Standards

- **Test Classes**: Use descriptive class names ending with `IntegrationTest`
- **Test Constants**: Use `private static final` with descriptive, ALL_CAPS naming with underscores
- **Test Methods**: Use descriptive method names that explain the scenario in camelCase
- **Two Test Method Styles**:
  - **User Action Style**: `aNonMigratedUserAddsABackupSMSMFA()` - focuses on business scenario and user behavior
  - **Technical Style**: `shouldReturn400WhenInvalidOTPEnteredWhenAddingSMSBackupMFA()` - includes technical details like HTTP status codes
- **@DisplayName**: Use human-readable descriptions with sentence case and proper grammar
- **@Nested Classes**: Use descriptive class names organized by functional behavior (e.g., `SuccessfulMFACreation`, `ErrorCases`)
- **Setup Methods**: Use descriptive method name `setUp()` for @BeforeEach
- **Helper Methods**: Use descriptive method names that explain the setup or operation
- **Parameterized Test Data**: Include descriptive names as first parameter for test identification

## Class Structure

### Base Class Extension
```java
class HandlerNameIntegrationTest extends ApiGatewayHandlerIntegrationTest
```

Extending `ApiGatewayHandlerIntegrationTest` provides essential infrastructure for testing API Gateway lambda handlers. The base class sets up LocalStack containers, manages test lifecycle, and provides utility methods for common operations.

**Key Benefits:**
- Pre-configured LocalStack environment with AWS services (DynamoDB, SQS, etc.)
- Built-in test data stores (`userStore`, `clientStore`)
- Queue management for notifications and audit events
- Request/response handling utilities

**Common Base Class Methods:**
```java
// Making API requests
var response = makeRequest(requestBody, headers, queryParams, pathParams, requestContext);

// Accessing test infrastructure
userStore.signUp(TEST_EMAIL, TEST_PASSWORD);
notificationsQueue.clear();
txmaAuditQueue.clear();
redis.generateAndSavePhoneNumberCode(TEST_EMAIL, 9000);
```



### Test Constants
```java
private static final String TEST_EMAIL = "test@email.com";
private static final String TEST_PASSWORD = "test-password";
private static final String TEST_PHONE_NUMBER = "07700900000";
```
- Group related constants together

> **💡 Reusability Tip**: Consider extracting commonly used test constants into a shared helper interface (e.g., `TestConstants`) to promote reuse across multiple test classes and reduce duplication.

### Static Test Data
```java
private static final MFAMethod defaultPrioritySms =
        MFAMethod.smsMfaMethod(
                true,
                true,
                TEST_PHONE_NUMBER_WITH_COUNTRY_CODE,
                PriorityIdentifier.DEFAULT,
                UUID.randomUUID().toString());
```
- Create reusable test data objects as static final fields
- Use builder patterns or factory methods when available
- Format multi-parameter method calls with one parameter per line

## JUnit Extensions

JUnit Extensions provide additional functionality to enhance test execution and provide cross-cutting concerns for integration tests. The authentication API project uses custom extensions located in the `shared-test` module under the `uk.gov.di.authentication.sharedtest.extensions` package. These extensions can be applied at the class or method level using the `@ExtendWith` annotation to add capabilities such as test data setup, environment configuration, or specialized test lifecycle management. Common extensions include database setup extensions, mock service extensions, and test environment configuration extensions that automatically configure LocalStack services or initialize test data stores.

The `ApiGatewayHandlerIntegrationTest` base class automatically provides access to essential test infrastructure including pre-configured data stores (`userStore`, `clientStore`), message queues (`notificationsQueue`, `txmaAuditQueue`), Redis cache, and configuration services. It also exposes utility methods like `makeRequest()` for simulating API Gateway requests, helper methods for test data manipulation, and automatic LocalStack container management for AWS service integration testing.

## JUnit Annotations

### @BeforeEach Setup
```java
@BeforeEach
void setUp() {
    handler = new HandlerClass(CONFIGURATION_SERVICE);
    userStore.signUp(TEST_EMAIL, TEST_PASSWORD);
    // Additional setup...
    notificationsQueue.clear();
    txmaAuditQueue.clear();
}
```
- Use `@BeforeEach` for test setup
- Initialize handler with required configuration
- Clear queues/state before each test

### @Nested Classes
```java
@Nested
class SuccessfulOperations {
    // Success scenario tests
}

@Nested
class ErrorCases {
    // Error scenario tests
}
```
- Group related tests using `@Nested` classes
- Organize by functional behavior, not technical implementation

### @DisplayName Usage
```java
@DisplayName("Non-migrated User adds a Backup SMS MFA")
@ParameterizedTest(name = "Default MFA: {0}")
@MethodSource("defaultMfaMethodProvider")
void aNonMigratedUserAddsABackupSMSMFA(String testName, MFAMethod defaultMfaMethod)
```
- Use `@DisplayName` for human-readable test descriptions
- For parameterized tests, include parameter placeholders in the name



## Parameterized Tests

### Method Source Pattern
```java
private static Stream<Arguments> defaultMfaMethodProvider() {
    return Stream.of(
            Arguments.of("Auth App", defaultPriorityAuthApp),
            Arguments.of("SMS", defaultPrioritySms));
}

@ParameterizedTest(name = "Default MFA: {0}")
@MethodSource("defaultMfaMethodProvider")
void testMethod(String testName, MFAMethod defaultMfaMethod)
```
- Use static methods returning `Stream<Arguments>` for test data
- Use `@MethodSource` with method name
- Include parameter names in `@ParameterizedTest(name = "...")`

## Test Structure

### Given-When-Then Pattern
```java
void testMethod() {
    // GIVEN (setup)
    setupNonMigratedUserWithMfaMethod(defaultMfaMethod);
    var otp = redis.generateAndSavePhoneNumberCode(TEST_EMAIL, 9000);
    
    // WHEN (action)
    var response = makeRequest(/* parameters */);
    
    // THEN (assertions)
    assertEquals(200, response.getStatusCode());
    assertUserMigrationStatus(true, "User should be migrated");
}
```
- Use comments to separate Given-When-Then sections
- Group setup, action, and assertion code clearly
- Use `var` for local variables when type is obvious

## Assertions

### Response Assertions
```java
assertEquals(200, response.getStatusCode(), "Expected successful response");
assertThat(response, hasJsonBody(ErrorResponse.ERROR_1020));
```
- Include descriptive assertion messages
- Use custom matchers like `hasJsonBody()` for complex assertions
- Assert status code first, then response body

### State Assertions
```java
assertUserMigrationStatus(true, "User should be migrated after adding backup MFA");
assertTrue(retrievedSmsMethod.isEnabled());
assertTrue(retrievedSmsMethod.isMethodVerified());
```
- Create helper methods for complex state assertions
- Include descriptive messages explaining expected state
- Use specific assertion methods (`assertTrue`, `assertEquals`) over generic ones

## Helper Methods and Classes

### AuditEventExpectation Pattern
```java
private void verifyAuditEvents(
        List<AuditableEvent> expectedEvents,
        Map<String, Map<String, String>> eventExpectations) {
    
    List<String> receivedEvents = assertTxmaAuditEventsReceived(txmaAuditQueue, expectedEvents);
    
    for (Map.Entry<String, Map<String, String>> eventEntry : eventExpectations.entrySet()) {
        AuditEventExpectation expectation = new AuditEventExpectation(eventEntry.getKey());
        
        for (Map.Entry<String, String> attributeEntry : eventEntry.getValue().entrySet()) {
            expectation.withAttribute(attributeEntry.getKey(), attributeEntry.getValue());
        }
        
        expectation.verify(receivedEvents);
    }
}
```
- Use `AuditEventExpectation` helper class for audit event verification
- Create reusable helper methods for common assertion patterns
- Use builder pattern for complex expectation setup

### Setup Helper Methods
```java
private void setupNonMigratedUserWithMfaMethod(MFAMethod mfaMethod) {
    if (mfaMethod.getMfaMethodType().equalsIgnoreCase("AUTH_APP")) {
        userStore.addMfaMethodSupportingMultiple(TEST_EMAIL, mfaMethod);
    } else {
        userStore.addVerifiedPhoneNumber(TEST_EMAIL, mfaMethod.getDestination());
    }
    userStore.setMfaMethodsMigrated(TEST_EMAIL, false);
    assertUserMigrationStatus(false, "User should not be migrated");
}
```
- Create helper methods for common test setup scenarios
- Include verification of setup state

### Request Construction
```java
private static String constructRequestBody(
        PriorityIdentifier priorityIdentifier, MfaDetail mfaDetail) {
    return format(
            """
            {
              "mfaMethod": {
                "priorityIdentifier": "%s",
                "method": %s
              }
            }
            """,
            priorityIdentifier, constructRequestMfaDetailJson(mfaDetail));
}
```
- Use text blocks for JSON construction
- Create helper methods for request/response construction
- Use `String.format()` for dynamic content

## Import Organization

### Static Imports
```java
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.BACKUP;
```
- Group static imports by package
- Import assertion methods statically
- Import commonly used constants statically

### Regular Imports
```java
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import uk.gov.di.authentication.sharedtest.helper.AuditEventExpectation;
```
- Organize imports by package hierarchy
- Use specific imports rather than wildcards
- Import test helper classes from shared test packages

## Error Testing Patterns

### Error Response Testing
```java
@Test
void shouldReturn400WhenInvalidCondition() {
    // Setup invalid condition
    
    var response = makeRequest(/* invalid parameters */);
    
    assertEquals(400, response.getStatusCode());
    assertThat(response, hasJsonBody(ErrorResponse.ERROR_CODE));
}
```
- Test method names should start with `shouldReturn` for error cases
- Include expected status code and error response
- Test one error condition per test method

### Audit Event Verification for Errors
```java
List<AuditableEvent> expectedEvents = List.of(AUTH_MFA_METHOD_ADD_FAILED);
Map<String, Map<String, String>> eventExpectations = new HashMap<>();
// ... setup expectations
verifyAuditEvents(expectedEvents, eventExpectations);
```
- Verify audit events are generated for error cases
- Use consistent pattern for audit event verification
- Include relevant attributes in audit event expectations

## Appendix: Available JUnit Extensions

> **Note**: This list may not be complete as new extensions may be added to the project over time. Check the `orchestration-shared-test/src/main/java/uk/gov/di/orchestration/sharedtest/extensions/` directory for the most current list of available extensions.

| Extension | Method/Feature | Purpose |
|-----------|----------------|----------|
| `AuditSnsTopicExtension` | `@ExtendWith(AuditSnsTopicExtension.class)` | Creates SNS topic for audit event testing with HTTP subscription |
| `AuthExternalApiStubExtension` | `@ExtendWith(AuthExternalApiStubExtension.class)` | Provides HTTP stub for external authentication API with token and userinfo endpoints |
| `AuthenticationCallbackUserInfoStoreExtension` | `@ExtendWith(AuthenticationCallbackUserInfoStoreExtension.class)` | Manages DynamoDB table for authentication callback user info storage |
| `ClientStoreExtension` | `@ExtendWith(ClientStoreExtension.class)` | Provides DynamoDB-based client registry with builder pattern for test clients |
| `CriStubExtension` | `@ExtendWith(CriStubExtension.class)` | HTTP stub for Credential Issuer (CRI) services with signed JWT responses |
| `DocAppJwksExtension` | `@ExtendWith(DocAppJwksExtension.class)` | Serves JWKS endpoint for document app public key verification |
| `DocumentAppCredentialStoreExtension` | `@ExtendWith(DocumentAppCredentialStoreExtension.class)` | Manages DynamoDB storage for document app credentials |
| `DynamoExtension` | `@ExtendWith(DynamoExtension.class)` | Base extension for DynamoDB table creation and management |
| `IPVStubExtension` | `@ExtendWith(IPVStubExtension.class)` | HTTP stub for Identity Proofing and Verification (IPV) service |
| `IdentityStoreExtension` | `@ExtendWith(IdentityStoreExtension.class)` | Manages DynamoDB tables for identity credentials and core identity JWT storage |
| `KmsKeyExtension` | `@ExtendWith(KmsKeyExtension.class)` | Creates and manages KMS keys for encryption and signing operations |
| `OrchAuthCodeExtension` | `@ExtendWith(OrchAuthCodeExtension.class)` | Manages DynamoDB table for orchestration authorization codes |
| `OrchClientSessionExtension` | `@ExtendWith(OrchClientSessionExtension.class)` | Provides DynamoDB-based client session management for orchestration |
| `OrchSessionExtension` | `@ExtendWith(OrchSessionExtension.class)` | Manages DynamoDB table for orchestration session data |
| `ParameterStoreExtension` | `@ExtendWith(ParameterStoreExtension.class)` | Creates and manages AWS Systems Manager Parameter Store entries |
| `RedisExtension` | `@ExtendWith(RedisExtension.class)` | Provides Redis connection management with data cleanup |
| `RpPublicKeyCacheExtension` | `@ExtendWith(RpPublicKeyCacheExtension.class)` | Manages DynamoDB cache for relying party public keys |
| `SnsTopicExtension` | `@ExtendWith(SnsTopicExtension.class)` | Creates SNS topics with HTTP subscription for message testing |
| `SqsQueueExtension` | `@ExtendWith(SqsQueueExtension.class)` | Creates and manages SQS queues with message retrieval utilities |
| `StateStorageExtension` | `@ExtendWith(StateStorageExtension.class)` | Provides DynamoDB-based state storage for session management |
| `TokenSigningExtension` | `@ExtendWith(TokenSigningExtension.class)` | Extends KmsKeyExtension to provide JWT signing capabilities using KMS |
| `UserStoreExtension` | `@ExtendWith(UserStoreExtension.class)` | Manages DynamoDB tables for user profiles and credentials with signup utilities |