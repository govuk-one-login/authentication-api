package uk.gov.di.authentication.frontendapi.helpers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.entity.UserProfile;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static uk.gov.di.authentication.frontendapi.helpers.PasskeyRegistrationPromptHelper.shouldSuppressPasskeyRegistrationPrompt;

class PasskeyRegistrationPromptHelperTest {
    private static final LocalDateTime NOW = LocalDateTime.now(ZoneId.of("UTC"));
    private static final String TWO_WEEKS_AGO = NOW.minusWeeks(2).toString();
    private static final String JUST_LESS_THAN_ONE_WEEK_AGO =
            NOW.minusWeeks(1).plusMinutes(5).toString();
    private static final String JUST_OVER_ONE_WEEK_AGO =
            NOW.minusWeeks(1).minusMinutes(5).toString();
    private static final String YESTERDAY = NOW.minusDays(1).toString();
    private static final String TWO_HOURS_ONE_MINUTE_AGO = NOW.minusMinutes(121).toString();
    private static final String ONE_HOUR_59_AGO = NOW.minusMinutes(119).toString();
    private static final String THIRTY_MINUTES_AGO = NOW.minusMinutes(30).toString();
    private static final String ONE_MINUTE_AGO = NOW.minusMinutes(1).toString();
    private static final String JUST_OVER_FIVE_MINUTES_AGO =
            NOW.minusMinutes(5).minusSeconds(1).toString();
    private static final String JUST_UNDER_FIVE_MINUTES_AGO =
            NOW.minusMinutes(5).plusSeconds(1).toString();
    private static final long ONE_WEEK_DURATION_IN_MINUTES = 60 * 24 * 7;
    private static final long FIVE_MINUTES = 5;

    private static Stream<Arguments> accountCreatedDateTimesToExpectedShouldSuppressPrompts() {
        return Stream.of(
                Arguments.of(YESTERDAY, false),
                Arguments.of(TWO_HOURS_ONE_MINUTE_AGO, false),
                Arguments.of(ONE_HOUR_59_AGO, true),
                Arguments.of(THIRTY_MINUTES_AGO, true));
    }

    @ParameterizedTest
    @MethodSource("accountCreatedDateTimesToExpectedShouldSuppressPrompts")
    void shouldSuppressPasskeyRegistrationPromptShouldReturnTrueIfAccountLessThan2HoursOld(
            String createdAtTimestamp, boolean expectedResult) {
        var userProfile = new UserProfile().withCreated(createdAtTimestamp);

        assertEquals(expectedResult, shouldSuppressPasskeyRegistrationPrompt(userProfile, 5L));
    }

    @Test
    void shouldSuppressPasskeyRegistrationPromptShouldReturnFalseIfAccountTimestampIsNull() {
        var userProfile = new UserProfile();

        assertFalse(shouldSuppressPasskeyRegistrationPrompt(userProfile, FIVE_MINUTES));
    }

    @Test
    void shouldSuppressPasskeyRegistrationPromptShouldReturnFalseIfAccountTimestampIsEmpty() {
        var userProfile = new UserProfile().withCreated("");

        assertFalse(shouldSuppressPasskeyRegistrationPrompt(userProfile, FIVE_MINUTES));
    }

    @Test
    void shouldSuppressPasskeyRegistrationPromptShouldReturnFalseIfAccountTimestampDoesNotParse() {
        var userProfile = new UserProfile().withCreated("not a parseable local date time");

        assertFalse(shouldSuppressPasskeyRegistrationPrompt(userProfile, FIVE_MINUTES));
    }

    private static Stream<Arguments> userSkippedTimestampsToExpectedShouldSuppressPrompt() {
        return Stream.of(
                Arguments.of(null, ONE_WEEK_DURATION_IN_MINUTES, false),
                Arguments.of(null, FIVE_MINUTES, false),
                Arguments.of(TWO_WEEKS_AGO, ONE_WEEK_DURATION_IN_MINUTES, false),
                Arguments.of(JUST_LESS_THAN_ONE_WEEK_AGO, ONE_WEEK_DURATION_IN_MINUTES, true),
                Arguments.of(JUST_OVER_ONE_WEEK_AGO, ONE_WEEK_DURATION_IN_MINUTES, false),
                Arguments.of(JUST_LESS_THAN_ONE_WEEK_AGO, FIVE_MINUTES, false),
                Arguments.of(YESTERDAY, ONE_WEEK_DURATION_IN_MINUTES, true),
                Arguments.of(YESTERDAY, FIVE_MINUTES, false),
                Arguments.of(JUST_OVER_FIVE_MINUTES_AGO, FIVE_MINUTES, false),
                Arguments.of(JUST_UNDER_FIVE_MINUTES_AGO, FIVE_MINUTES, true),
                Arguments.of(ONE_MINUTE_AGO, FIVE_MINUTES, true));
    }

    @ParameterizedTest
    @MethodSource("userSkippedTimestampsToExpectedShouldSuppressPrompt")
    void
            shouldSuppressPasskeyRegistrationPromptShouldReturnTrueIfUserHasRecentlySkippedPasskeyRegistration(
                    String skippedTimestamp, Long configuredDuration, boolean expectedResult) {
        var userProfile =
                new UserProfile()
                        .withCreated(TWO_WEEKS_AGO)
                        .withLastSkippedAddingPasskey(skippedTimestamp);

        assertEquals(
                expectedResult,
                shouldSuppressPasskeyRegistrationPrompt(userProfile, configuredDuration));
    }

    @Test
    void
            shouldSuppressPasskeyRegistrationPromptShouldReturnFalseIfLastSkippedTimestampDoesNotParse() {
        var userProfile =
                new UserProfile()
                        .withCreated(TWO_WEEKS_AGO)
                        .withLastSkippedAddingPasskey("not a parseable local date time");

        assertFalse(shouldSuppressPasskeyRegistrationPrompt(userProfile, FIVE_MINUTES));
    }
}
