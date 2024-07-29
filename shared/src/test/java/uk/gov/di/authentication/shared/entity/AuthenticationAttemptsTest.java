package uk.gov.di.authentication.shared.entity;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
}
