package uk.gov.di.authentication.shared.entity;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.validation.RequiredFieldValidator;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthenticationAttemptsTest {
    private static final String INTERNAL_SUB_ID = "internalSubjectId";
    private static final JourneyType JOURNEY_TYPE = JourneyType.REAUTHENTICATION;
    private static final String CREATED_DATE = "2024-07-29T10:00:00Z";
    private static final String UPDATED_DATE = "2024-07-29T10:30:00Z";
    private static final CountType COUNT_TYPE = CountType.ENTER_MFA_CODE;
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
        attempts.setCountType(COUNT_TYPE);

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
                JOURNEY_TYPE + "#" + COUNT_TYPE + "#" + "Count",
                attempts.getSortKey(),
                "getJourneyTypeAuthMethod should return "
                        + JOURNEY_TYPE
                        + "#"
                        + COUNT_TYPE
                        + "#"
                        + "COUNT");
    }

    @Test
    void testValidationWithMissingRequiredFields() {
        AuthenticationAttempts attempts = new AuthenticationAttempts();
        // Intentionally not setting any fields to check for validation errors

        RequiredFieldValidator validator = new RequiredFieldValidator();
        List<String> violations = validator.validate(attempts);

        // Check that all required fields are reported as missing
        assertTrue(violations.contains("internalSubjectId"));
        assertTrue(violations.contains("countType"));
        assertTrue(violations.contains("count"));
        assertTrue(violations.contains("journeyType"));
    }

    @Test
    void testValidationWithAllFieldsSet() {
        AuthenticationAttempts attempts =
                new AuthenticationAttempts()
                        .withInternalSubjectId(INTERNAL_SUB_ID)
                        .withCountType(COUNT_TYPE)
                        .withJourneyType(JOURNEY_TYPE)
                        .withCount(3)
                        .withTimeToLive(TTL);

        RequiredFieldValidator validator = new RequiredFieldValidator();
        List<String> violations = validator.validate(attempts);

        assertTrue(violations.isEmpty());
    }
}
