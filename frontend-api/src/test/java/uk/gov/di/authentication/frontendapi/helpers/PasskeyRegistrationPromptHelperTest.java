package uk.gov.di.authentication.frontendapi.helpers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.entity.UserProfile;

import java.time.LocalDateTime;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static uk.gov.di.authentication.frontendapi.helpers.PasskeyRegistrationPromptHelper.shouldSuppressPasskeyRegistrationPrompt;

class PasskeyRegistrationPromptHelperTest {
    private static final String YESTERDAY = LocalDateTime.now().minusDays(1).toString();
    private static final String TWO_HOURS_ONE_MINUTE_AGO =
            LocalDateTime.now().minusMinutes(121).toString();
    private static final String ONE_HOUR_59_AGO = LocalDateTime.now().minusMinutes(119).toString();
    private static final String THIRTY_MINUTES_AGO =
            LocalDateTime.now().minusMinutes(30).toString();

    private static Stream<Arguments> dateTimesToExpectedShouldSuppressPrompts() {
        return Stream.of(
                Arguments.of(YESTERDAY, false),
                Arguments.of(TWO_HOURS_ONE_MINUTE_AGO, false),
                Arguments.of(ONE_HOUR_59_AGO, true),
                Arguments.of(THIRTY_MINUTES_AGO, true));
    }

    @ParameterizedTest
    @MethodSource("dateTimesToExpectedShouldSuppressPrompts")
    void shouldSuppressPasskeyRegistrationPromptShouldReturnTrueIfAccountLessThan2HoursOld(
            String createdAtTimestamp, boolean expectedResult) {
        var userProfile = new UserProfile().withCreated(createdAtTimestamp);

        assertEquals(expectedResult, shouldSuppressPasskeyRegistrationPrompt(userProfile));
    }

    @Test
    void shouldSuppressPasskeyRegistrationPromptShouldReturnFalseIfAccountTimestampIsNull() {
        var userProfile = new UserProfile();

        assertFalse(shouldSuppressPasskeyRegistrationPrompt(userProfile));
    }

    @Test
    void shouldSuppressPasskeyRegistrationPromptShouldReturnFalseIfAccountTimestampIsEmpty() {
        var userProfile = new UserProfile().withCreated("");

        assertFalse(shouldSuppressPasskeyRegistrationPrompt(userProfile));
    }

    @Test
    void shouldSuppressPasskeyRegistrationPromptShouldReturnFalseIfAccountTimestampDoesNotParse() {
        var userProfile = new UserProfile().withCreated("not a parseable local date time");

        assertFalse(shouldSuppressPasskeyRegistrationPrompt(userProfile));
    }
}
