# Unit Test Rules

## Fundamental Requirements

- All unit tests must compile without errors
- All unit tests must run successfully and pass
- All unit tests must have no warnings (unused imports, unchecked operations, etc.)
- All unit tests must pass static analysis tools (e.g., SonarQube) without issues

## Structure and Organization

### Test Class Structure

- Use `@Nested` classes to group related test scenarios (e.g., `WhenUserExists`, `ErrorCases`)
- Use descriptive class names ending with `Test`
- Place test classes in the same package structure as the class under test

### Test Method Naming

- Use descriptive method names that explain what is being tested
- Follow pattern: `should[ExpectedBehavior]_when[StateUnderTest]` or `should[ExpectedBehavior]If[Condition]`
- Use `@ParameterizedTest` with `@MethodSource` for testing multiple similar scenarios
- Use `@DisplayName` annotations sparingly, only when method names cannot be descriptive enough

## Setup and Initialization

### Mock Dependencies

- Use `mock()` method to create mock dependencies
- Initialize mocks as `private final` fields or in `@BeforeEach` method
- Use `reset()` to clear mock interactions between tests when necessary

### Test Data Setup

```java
@BeforeEach
void setUp() {
    // Initialize class under test with mocked dependencies
    classUnderTest = new ClassUnderTest(mockDependency);

    // Set up common test data
    when(configurationService.getSomeValue()).thenReturn(DEFAULT_VALUE);
}
```

### Test Constants

- Define all test data as `private static final` constants at class level
- Use meaningful names (e.g., `TEST_EMAIL`, `VALID_CODE`, `CLIENT_ID`)
- Group related constants together
- Use realistic test data that represents actual usage

## Mocking and Stubbing

### Mock Behavior Setup

- Use `when().thenReturn()` for simple return values
- Use `when().thenThrow()` for exception scenarios
- Set up mocks in `@BeforeEach` for common behavior
- Set up specific mock behavior in individual tests when needed

### Mock Verification

- Use `verify()` to assert that methods were called with expected parameters
- Use `verifyNoInteractions()` when no interactions are expected
- Use `times()` to verify specific number of method calls
- Verify mock interactions after assertions about return values

## Assertions

### Assertion Libraries

- Use JUnit 5 assertions (`assertEquals`, `assertTrue`, `assertFalse`, `assertThrows`)
- Use Hamcrest matchers for complex assertions (`assertThat`, `equalTo`, `hasItem`)
- Use custom matchers when available (e.g., `hasStatus`, `hasJsonBody`)
- **Avoid `assertEquals` where possible** - it only shows "true vs false" differences which are not useful for debugging
- **Prefer `assertThat` with descriptive matchers** for better failure messages

### Assertion Guidelines

- **Include failure messages** for non-trivial assertions or when expectations are not obvious
- Use descriptive failure messages that explain what was expected vs what was received
- For complex objects, use `assertThat` with specific matchers rather than `assertEquals`

### Assertion Patterns

```java
// Preferred - descriptive assertions with good failure messages
assertThat(result.getStatus(), equalTo(200), "Expected successful response status");
assertThat(user.isActive(), is(true), "User should be active after registration");
assertThat(response.getErrors(), hasSize(2), "Expected exactly 2 validation errors");

// Avoid - poor failure messages
assertEquals(200, result.getStatus()); // Only shows "false" on failure
assertTrue(user.isActive()); // Only shows "false" on failure

// Exception assertions with descriptive messages
var exception = assertThrows(ValidationException.class,
    () -> validator.validate(invalidInput),
    "Should throw ValidationException for invalid input");
assertThat(exception.getMessage(), containsString("email format"));
```

### Response Validation

- Assert status codes first for HTTP responses
- Use custom matchers for JSON response validation when available
- Parse response bodies when checking specific fields

## Parameterized Tests

### Test Data Sources

- Use `@MethodSource` with static methods returning `Stream<Arguments>`
- Name source methods descriptively (e.g., `invalidEmailAddresses`, `validPhoneNumbers`)
- Group related test parameters logically

### Parameter Naming

```java
@ParameterizedTest
@MethodSource("invalidInputParameters")
void shouldReturnError_whenInputIsInvalid(String input, ErrorResponse expectedError) {
    // Test implementation
}

private static Stream<Arguments> invalidInputParameters() {
    return Stream.of(
        Arguments.of("", ErrorResponse.EMPTY_INPUT),
        Arguments.of("invalid", ErrorResponse.INVALID_FORMAT)
    );
}
```

## Error Testing

### Exception Testing

- Test all expected error conditions
- Use `assertThrows()` to verify exceptions are thrown
- Verify exception messages when relevant
- Test both the exception type and any error details

### Error Response Testing

- Test error status codes and response bodies
- Verify appropriate error messages are returned
- Test edge cases and boundary conditions

## Best Practices

### Test Independence

- Each test should be independent and not rely on other tests
- Use `@BeforeEach` and `@AfterEach` for setup and cleanup
- Clear mock state between tests when necessary

### Test Data Management

- Use helper methods to create common test objects
- Use builders or factory methods for complex test data
- Keep test data realistic and representative

### Code Organization

- Keep test methods focused on single scenarios
- Extract common setup logic into helper methods
- Use meaningful variable names that explain the test context
- Remove unused imports and variables
- Group related tests using `@Nested` classes
- **Organize tests so that happy path scenarios are always first** - success cases should come before error cases

### Performance Considerations

- Avoid expensive operations in test setup
- Use mocks instead of real dependencies
- Keep tests fast and focused

### Test Formatting

- **Use Given/When/Then comments** for tests with non-trivial setup or checking to clearly separate test phases
- **Make the subject under test line clear** by having a blank line before and after it, and add a "When" comment if the test is non-trivial
- This helps identify what is being tested at a glance

### Documentation

- Use clear and descriptive test method names
- Add comments for complex test logic
- Document test data setup when non-obvious

## Common Patterns

### Testing Service Classes

```java
class ServiceClassTest {
    private final DependencyService dependencyService = mock(DependencyService.class);
    private ServiceClass serviceClass;

    @BeforeEach
    void setUp() {
        serviceClass = new ServiceClass(dependencyService);
    }

    @Test
    void shouldReturnExpectedResult_whenValidInput() {
        // Given
        when(dependencyService.someMethod()).thenReturn(expectedValue);

        // When
        var result = serviceClass.methodUnderTest(input);

        // Then
        assertThat(result, equalTo(expectedResult), "Service should return expected result for valid input");
        verify(dependencyService).someMethod();
    }
}
```

### Testing Lambda Handlers

```java
class HandlerTest {
    private final Context context = mock(Context.class);
    private final Service service = mock(Service.class);
    private Handler handler;

    @BeforeEach
    void setUp() {
        handler = new Handler(service);
    }

    @Test
    void shouldReturn200_whenValidRequest() {
        // Given
        var request = createValidRequest();

        // When
        var response = handler.handleRequest(request, context);

        // Then
        assertThat(response, hasStatus(200));
        verify(service).processRequest(any());
    }
}
```
