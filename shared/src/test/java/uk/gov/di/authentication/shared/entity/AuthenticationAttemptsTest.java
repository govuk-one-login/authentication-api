package uk.gov.di.authentication.shared.entity;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.validation.RequiredFieldValidator;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthenticationAttemptsTest {
    private static final String INTERNAL_SUB_ID = "internalSubjectId";
    private static final String JOURNEY_TYPE = "sign-in";
    private static final String CREATED_DATE = "2024-07-29T10:00:00Z";
    private static final String UPDATED_DATE = "2024-07-29T10:30:00Z";
    private static final String MFA_CODE = "123456";
    private static final String MFA_METHOD = "AUTH_APP";
    private static final long TTL = 1234567890L;

    @Test
    void testFluentSetters() {
        AuthenticationAttempts attempts = new AuthenticationAttempts();

        AuthenticationAttempts result = attempts.withInternalSubjectId(INTERNAL_SUB_ID);
        assertEquals(INTERNAL_SUB_ID, result.getInternalSubjectId());

        result = attempts.withUpdated(UPDATED_DATE);
        assertEquals(UPDATED_DATE, result.getUpdated());

        result = attempts.withCreated(CREATED_DATE);
        assertEquals(CREATED_DATE, result.getCreated());

        result = attempts.withTimeToLive(TTL);
        assertEquals(TTL, result.getTimeToLive());

        result = attempts.withCode(MFA_CODE);
        assertEquals(MFA_CODE, result.getCode());
    }

    @Test
    void testGettersAndSetters() {
        AuthenticationAttempts attempts = new AuthenticationAttempts();

        attempts.withInternalSubjectId(INTERNAL_SUB_ID);
        assertEquals(
                INTERNAL_SUB_ID,
                attempts.getInternalSubjectId(),
                "getAttemptIdentifier should return " + INTERNAL_SUB_ID);

        attempts.setJourneyType(JOURNEY_TYPE);
        assertEquals(
                JOURNEY_TYPE,
                attempts.getJourneyType(),
                "getJourneyType should return " + JOURNEY_TYPE);

        attempts.setAuthenticationMethod(MFA_METHOD);
        assertEquals(
                MFA_METHOD,
                attempts.getAuthenticationMethod(),
                "getAuthenticationMethod should return " + MFA_METHOD);

        attempts.setCode(MFA_CODE);
        assertEquals(MFA_CODE, attempts.getCode(), "getCode should return " + MFA_CODE);

        attempts.setCount(3);
        assertEquals(3, attempts.getCount(), "getCount should return 3");

        attempts.setTimeToLive(TTL);
        assertEquals(TTL, attempts.getTimeToLive(), "getTimeToLive should return " + TTL);

        attempts.setCreated(CREATED_DATE);
        assertEquals(
                CREATED_DATE, attempts.getCreated(), "getCreated should return " + CREATED_DATE);

        attempts.setUpdated(UPDATED_DATE);
        assertEquals(
                UPDATED_DATE, attempts.getUpdated(), "getUpdated should return " + UPDATED_DATE);

        assertEquals(
                MFA_METHOD + "_" + JOURNEY_TYPE,
                attempts.getAuthMethodJourneyType(),
                "getAuthMethodJourneyType should return " + MFA_METHOD + "_" + JOURNEY_TYPE);
    }

    @Test
    void testValidationWithMissingRequiredFields() {
        AuthenticationAttempts attempts = new AuthenticationAttempts();
        // Intentionally not setting any fields to check for validation errors

        RequiredFieldValidator validator = new RequiredFieldValidator();
        List<String> violations = validator.validate(attempts);

        // Check that all required fields are reported as missing
        assertTrue(violations.contains("internalSubjectId"));
        assertTrue(violations.contains("authenticationMethod"));
        assertTrue(violations.contains("code"));
        assertTrue(violations.contains("count"));
        assertTrue(violations.contains("journeyType"));
    }

    @Test
    void testValidationWithAllFieldsSet() {
        AuthenticationAttempts attempts =
                new AuthenticationAttempts()
                        .withInternalSubjectId(INTERNAL_SUB_ID)
                        .withAuthenticationMethod(MFA_METHOD)
                        .withCode(MFA_CODE)
                        .withJourneyType(JOURNEY_TYPE)
                        .withCount(3)
                        .withTimeToLive(TTL);

        RequiredFieldValidator validator = new RequiredFieldValidator();
        List<String> violations = validator.validate(attempts);

        assertTrue(violations.isEmpty());
    }
}
