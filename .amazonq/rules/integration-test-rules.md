# Integration Test Rules

## Fundamental Requirements

- All integration tests must compile without errors
- All integration tests must run successfully and pass
- All integration tests must have no warnings (unused imports, unchecked operations, etc.)
- All integration tests must pass static analysis tools (e.g., SonarQube) without issues

## Structure and Organization

### Test Class Structure
- Extend `ApiGatewayHandlerIntegrationTest` base class
- Use `@Nested` classes to group related test scenarios (e.g., `SuccessfulMFACreation`, `ErrorCases`)
- Use descriptive class names ending with `IntegrationTest`

### Test Method Naming
- Use `@DisplayName` annotations for clear test descriptions
- Method names should be written from the perspective of what the user is doing (success paths) and what has prevented the user completing an action (error paths)
- Use `@ParameterizedTest` with `@MethodSource` for testing multiple similar scenarios

## Setup and Initialization

### BeforeEach Setup
```java
@BeforeEach
void setUp() {
    handler = new HandlerClass(CONFIGURATION_SERVICE);
    userStore.signUp(TEST_EMAIL, TEST_PASSWORD);
    // Calculate subject identifiers
    testPublicSubject = userStore.getUserProfileFromEmail(TEST_EMAIL).get().getPublicSubjectID();
    byte[] salt = userStore.addSalt(TEST_EMAIL);
    testInternalSubject = ClientSubjectHelper.calculatePairwiseIdentifier(/*...*/);
    // Clear queues
    notificationsQueue.clear();
    txmaAuditQueue.clear();
}
```

### Test Constants
- Define all test data as `private static final` constants at class level
- Use meaningful names (e.g., `TEST_EMAIL`, `TEST_PHONE_NUMBER_WITH_COUNTRY_CODE`)
- Group related constants together

## Request Construction

### Headers
- Always include required headers in a `Map<String, String>`
- Include audit headers when testing audit events: `headers.put(TXMA_AUDIT_ENCODED_HEADER, "ENCODED_DEVICE_DETAILS")`

### Request Body
- Use helper methods to construct request bodies consistently
- Pass request body as `Optional.of(requestBody)` to `makeRequest()`

### Path and Query Parameters
- Use separate maps for path parameters and query parameters
- Example: `Map.of("publicSubjectId", testPublicSubject)` for path parameters

## Assertions

### Response Validation
- Always assert status code first: `assertThat(response, hasStatus(expectedStatusCode))`
- Do NOT add descriptive messages to `assertThat` calls with custom matchers - they don't support the 3-parameter form
- Use `assertThat(response, hasJsonBody(expectedResponse))` for JSON response validation
- Parse response body when checking specific fields: `objectMapper.readValue(response.getBody(), ResponseClass.class)`

### State Verification
- Verify database/store state changes after operations
- Use helper methods like `findMfaMethodByPriority()` for complex lookups
- Assert both positive and negative conditions where relevant

### Audit Event Verification
- Use `assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(EXPECTED_EVENTS))` directly
- Do NOT create wrapper methods for audit verification - call the helper directly
- Use `List.of()` without explicit generic types to avoid compilation issues

### Notification Verification
```java
assertNotificationsReceived(
    notificationsQueue,
    List.of(new NotifyRequest(email, notificationType, language))
);
```

## Error Testing

### Error Scenarios
- Test all expected error conditions in separate `@Nested` class
- Use descriptive test names explaining the error condition
- Assert both status code and error response body
- Verify appropriate audit events are still generated for errors

### Parameterized Error Tests
- Use `@ParameterizedTest` with `@MethodSource` for testing multiple invalid inputs
- Create static methods returning `Stream<Arguments>` for test data

## Best Practices

### Test Data Management
- Use helper methods to set up common test scenarios (e.g., `setupMigratedUserWithMfaMethod()`)
- Generate dynamic test data where appropriate (e.g., OTP codes, UUIDs)
- Clean up queues in `@BeforeEach` to ensure test isolation
- Avoid complex assertions in helper methods that may cause test failures
- Keep helper methods focused on setup, not validation
- Use accurate method names that reflect all operations performed - avoid hiding side effects (e.g., `setupUserAndSession()` not `setupMfa()` if it also creates users and sessions)

### Assertions
- Use descriptive assertion messages explaining what should happen
- Group related assertions together
- Use helper methods for complex assertion logic

### Code Organization
- Keep test methods focused on single scenarios
- Extract common setup logic into helper methods
- Use meaningful variable names that explain the test context
- Remove unused imports to eliminate compiler warnings
- Remove unnecessary exception declarations from method signatures if the exceptions are not actually thrown
- Ensure all method signatures include only necessary exception declarations
- **Validation step**: After standardization, verify each method's throws clause matches its actual usage:
  - Methods using `objectMapper.readValue()` need `throws JsonException`
  - Methods only using assertions and helper methods typically don't need exception declarations
  - Error test methods checking status codes without parsing response bodies don't need `JsonException`
- Use direct calls to existing helper methods rather than creating unnecessary wrapper methods
- Regularly check for and remove unused code (imports, variables, methods) to maintain clean code
- Prefer immutable collections (e.g., `Map.of()`, `List.of()`) over mutable ones when the collection won't be modified

### Documentation
- Use `@DisplayName` for human-readable test descriptions
- Add comments for complex test setup or assertions
- Group related tests using `@Nested` classes with descriptive names