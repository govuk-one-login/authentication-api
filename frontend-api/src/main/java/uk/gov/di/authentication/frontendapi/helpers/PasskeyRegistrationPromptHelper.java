package uk.gov.di.authentication.frontendapi.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.UserProfile;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeParseException;
import java.util.Objects;

public class PasskeyRegistrationPromptHelper {
    private static final Logger LOG = LogManager.getLogger(PasskeyRegistrationPromptHelper.class);

    private PasskeyRegistrationPromptHelper() {
        /* This utility class should not be instantiated */
    }

    public static boolean shouldSuppressPasskeyRegistrationPrompt(
            UserProfile userProfile, Long dontPromptAgainIfSkippedInMinutes) {
        return accountIsLessThanTwoHoursOld(userProfile)
                || userHasRecentlySkippedPasskeyRegistration(
                        userProfile, dontPromptAgainIfSkippedInMinutes);
    }

    private static boolean userHasRecentlySkippedPasskeyRegistration(
            UserProfile userProfile, Long dontPromptAgainInMinutesDuration) {
        var lastSkipped = userProfile.getLastSkippedAddingPasskey();
        if (Objects.isNull(lastSkipped)) {
            return false;
        } else {
            try {
                var earliestTimestampAfterWhichWeCanPromptAgain =
                        LocalDateTime.now(ZoneId.of("UTC"))
                                .minusMinutes(dontPromptAgainInMinutesDuration);
                var lastSkippedAsLocalDateTime =
                        LocalDateTime.parse(userProfile.getLastSkippedAddingPasskey());
                return lastSkippedAsLocalDateTime.isAfter(
                        earliestTimestampAfterWhichWeCanPromptAgain);
            } catch (DateTimeParseException e) {
                LOG.warn(
                        "last skipped adding passkey date on user profile could not be parsed as local date time, not suppressing create passkey prompt");
                return false;
            }
        }
    }

    private static boolean accountIsLessThanTwoHoursOld(UserProfile userProfile) {
        if (Objects.isNull(userProfile.getCreated()) || userProfile.getCreated().isEmpty()) {
            LOG.warn(
                    "created at date on user profile is null or empty, not suppressing create passkey prompt");
            return false;
        }
        try {
            var createdDate = LocalDateTime.parse(userProfile.getCreated());
            var nowMinusTwoHours = LocalDateTime.now(ZoneId.of("UTC")).minusHours(2);
            var shouldSuppressBasedOnAccountCreation = createdDate.isAfter(nowMinusTwoHours);
            if (shouldSuppressBasedOnAccountCreation) {
                LOG.info(
                        "suppressing passkey registration prompt as account is less than two hours old");
            }
            return shouldSuppressBasedOnAccountCreation;
        } catch (DateTimeParseException e) {
            LOG.warn(
                    "created at date on user profile could not be parsed as local date time, not suppressing create passkey prompt");
            return false;
        }
    }
}
