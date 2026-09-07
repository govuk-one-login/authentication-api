package uk.gov.di.authentication.shared.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.util.ArrayList;
import java.util.List;

public class InactiveAccountFailsafeCheckHelper {

    private static final Logger LOG =
            LogManager.getLogger(InactiveAccountFailsafeCheckHelper.class);

    static final long INACTIVITY_THRESHOLD_YEARS = 5;

    private static final DateTimeFormatter DATE_TIME_FORMATTER =
            new DateTimeFormatterBuilder()
                    .append(DateTimeFormatter.ISO_LOCAL_DATE_TIME)
                    .optionalStart()
                    .appendOffsetId()
                    .optionalEnd()
                    .toFormatter();

    public record ActivityCheckResult(boolean recentlyActive, String triggeringAttribute) {}

    private record TimestampCandidate(String timestamp, String label) {}

    private InactiveAccountFailsafeCheckHelper() {}

    public static ActivityCheckResult checkForRecentActivity(
            UserProfile userProfile, UserCredentials userCredentials, Clock clock) {
        var threshold = LocalDateTime.now(clock).minusYears(INACTIVITY_THRESHOLD_YEARS);

        return buildTimestampCandidates(userProfile, userCredentials).stream()
                .filter(candidate -> candidate.timestamp() != null)
                .filter(
                        candidate ->
                                isWithinActivityThreshold(
                                        candidate.timestamp(), candidate.label(), threshold))
                .findFirst()
                .map(candidate -> new ActivityCheckResult(true, candidate.label()))
                .orElse(new ActivityCheckResult(false, null));
    }

    private static boolean isWithinActivityThreshold(
            String timestamp, String label, LocalDateTime threshold) {
        try {
            return LocalDateTime.parse(timestamp, DATE_TIME_FORMATTER).isAfter(threshold);
        } catch (Exception e) {
            LOG.warn(
                    "Failed to parse timestamp '{}' from source '{}': {}",
                    timestamp,
                    label,
                    e.getMessage());
            return false;
        }
    }

    private static List<TimestampCandidate> buildTimestampCandidates(
            UserProfile userProfile, UserCredentials userCredentials) {
        var candidates = new ArrayList<TimestampCandidate>();

        candidates.add(new TimestampCandidate(userProfile.getCreated(), "UserProfile.Created"));
        candidates.add(new TimestampCandidate(userProfile.getUpdated(), "UserProfile.Updated"));

        TermsAndConditions tc = userProfile.getTermsAndConditions();
        candidates.add(
                new TimestampCandidate(
                        tc != null ? tc.getTimestamp() : null,
                        "UserProfile.termsAndConditions.timestamp"));

        candidates.add(
                new TimestampCandidate(userProfile.getLastSignedIn(), "UserProfile.LastSignedIn"));

        if (userCredentials != null) {
            candidates.add(
                    new TimestampCandidate(
                            userCredentials.getCreated(), "UserCredentials.Created"));
            candidates.add(
                    new TimestampCandidate(
                            userCredentials.getUpdated(), "UserCredentials.Updated"));
        }

        return candidates;
    }
}
