package uk.gov.di.authentication.shared.entity;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.validation.RequiredFieldValidator;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthenticationAttemptsTest {

    @Test
    void testFluentSetters() {
        AuthenticationAttempts attempts = new AuthenticationAttempts();

        AuthenticationAttempts result = attempts.withAttemptIdentifier("attempt-1234");
        assertEquals("attempt-1234", result.getAttemptIdentifier());

        result = attempts.withUpdated("2024-07-29T10:30:00Z");
        assertEquals("2024-07-29T10:30:00Z", result.getUpdated());

        result = attempts.withCreated("2024-07-29T10:00:00Z");
        assertEquals("2024-07-29T10:00:00Z", result.getCreated());

        result = attempts.withTimeToLive(1234567890L);
        assertEquals(1234567890L, result.getTimeToLive());

        result = attempts.withCode("code-5678");
        assertEquals("code-5678", result.getCode());
    }

    @Test
    void testGettersAndSetters() {
        AuthenticationAttempts attempts = new AuthenticationAttempts();

        attempts.setAttemptIdentifier("attempt-1234");
        assertEquals(
                "attempt-1234",
                attempts.getAttemptIdentifier(),
                "getAttemptIdentifier should return 'attempt-1234'");

        attempts.setJourneyType("login");
        assertEquals("login", attempts.getJourneyType(), "getJourneyType should return 'login'");

        attempts.setAuthenticationMethod("email");
        assertEquals(
                "email",
                attempts.getAuthenticationMethod(),
                "getAuthenticationMethod should return 'email'");

        attempts.setCode("code-5678");
        assertEquals("code-5678", attempts.getCode(), "getCode should return 'code-5678'");

        attempts.setCount(3);
        assertEquals(3, attempts.getCount(), "getCount should return 3");

        attempts.setTimeToLive(1234567890L);
        assertEquals(
                1234567890L, attempts.getTimeToLive(), "getTimeToLive should return 1234567890L");

        attempts.setCreated("2024-07-29T10:00:00Z");
        assertEquals(
                "2024-07-29T10:00:00Z",
                attempts.getCreated(),
                "getCreated should return '2024-07-29T10:00:00Z'");

        attempts.setUpdated("2024-07-29T10:30:00Z");
        assertEquals(
                "2024-07-29T10:30:00Z",
                attempts.getUpdated(),
                "getUpdated should return '2024-07-29T10:30:00Z'");
    }

    @Test
    void testValidationWithMissingRequiredFields() {
        AuthenticationAttempts attempts = new AuthenticationAttempts();
        // Intentionally not setting any fields to check for validation errors

        RequiredFieldValidator validator = new RequiredFieldValidator();
        List<String> violations = validator.validate(attempts);

        // Check that all required fields are reported as missing
        assertTrue(violations.contains("attemptIdentifier"));
        assertTrue(violations.contains("authenticationMethod"));
        assertTrue(violations.contains("code"));
        assertTrue(violations.contains("count"));
    }

    @Test
    void testValidationWithAllFieldsSet() {
        AuthenticationAttempts attempts =
                new AuthenticationAttempts()
                        .withAttemptIdentifier("attempt-1234")
                        .withAuthenticationMethod("email")
                        .withCode("code-5678")
                        .withCount(3)
                        .withTimeToLive(42L);

        RequiredFieldValidator validator = new RequiredFieldValidator();
        List<String> violations = validator.validate(attempts);

        assertTrue(violations.isEmpty());
    }
}
