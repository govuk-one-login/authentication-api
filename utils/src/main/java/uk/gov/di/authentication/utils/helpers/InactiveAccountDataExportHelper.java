package uk.gov.di.authentication.utils.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.KeysAndAttributes;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.utils.entity.InactiveAccountTrackerItem;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class InactiveAccountDataExportHelper {

    private static final Logger LOG = LogManager.getLogger(InactiveAccountDataExportHelper.class);
    private static final long BASE_BACKOFF_MS = 100;

    public record LastActiveDate(String timestamp, String source) {}

    private InactiveAccountDataExportHelper() {}

    public static List<Map<String, AttributeValue>> buildCredentialKeys(
            List<Map<String, AttributeValue>> userProfileItems) {
        List<Map<String, AttributeValue>> keys = new ArrayList<>();

        for (Map<String, AttributeValue> profileItem : userProfileItems) {
            AttributeValue email = profileItem.get(UserCredentials.ATTRIBUTE_EMAIL);
            if (email != null) {
                keys.add(Map.of(UserCredentials.ATTRIBUTE_EMAIL, email));
            }
        }

        return keys;
    }

    public static Map<String, KeysAndAttributes> extractUnprocessedKeys(
            BatchGetItemResponse response, String tableName) {
        Map<String, KeysAndAttributes> unprocessed = response.unprocessedKeys();
        if (unprocessed == null || unprocessed.isEmpty()) {
            return Map.of();
        }

        KeysAndAttributes keysAndAttrs = unprocessed.get(tableName);
        if (keysAndAttrs == null || keysAndAttrs.keys().isEmpty()) {
            return Map.of();
        }

        return new HashMap<>(unprocessed);
    }

    public static void backoff(int retryCount) {
        try {
            Thread.sleep(BASE_BACKOFF_MS * (1L << (retryCount - 1)));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOG.error("Backoff sleep interrupted during BatchGetItem retry");
        }
    }

    public static long countMissingCredentials(int requestedCount, int returnedCount) {
        return Math.max(0, requestedCount - returnedCount);
    }

    public static LastActiveDate calculateLastActiveDate(
            Map<String, AttributeValue> userProfileItem,
            Map<String, AttributeValue> userCredentialsItem) {
        List<TimestampCandidate> candidates =
                buildTimestampCandidates(userProfileItem, userCredentialsItem);

        LocalDateTime mostRecent = null;
        String mostRecentSource = null;

        for (TimestampCandidate candidate : candidates) {
            if (candidate.timestamp() == null) {
                continue;
            }

            try {
                LocalDateTime parsed = LocalDateTime.parse(candidate.timestamp());
                if (mostRecent == null || parsed.isAfter(mostRecent)) {
                    mostRecent = parsed;
                    mostRecentSource = candidate.source();
                }
            } catch (Exception e) {
                LOG.warn(
                        "Failed to parse timestamp '{}' from source '{}': {}",
                        candidate.timestamp(),
                        candidate.source(),
                        e.getMessage());
            }
        }

        if (mostRecent == null) {
            return null;
        }

        return new LastActiveDate(mostRecent.toString(), mostRecentSource);
    }

    private static List<TimestampCandidate> buildTimestampCandidates(
            Map<String, AttributeValue> userProfileItem,
            Map<String, AttributeValue> userCredentialsItem) {
        List<TimestampCandidate> candidates = new ArrayList<>();

        if (userProfileItem != null) {
            candidates.add(
                    new TimestampCandidate(
                            getStringAttribute(userProfileItem, "Created"), "UserProfile.Created"));
            candidates.add(
                    new TimestampCandidate(
                            getStringAttribute(userProfileItem, "Updated"), "UserProfile.Updated"));
            candidates.add(
                    new TimestampCandidate(
                            getTermsAndConditionsTimestamp(userProfileItem),
                            "UserProfile.termsAndConditions.timestamp"));
        }

        if (userCredentialsItem != null) {
            candidates.add(
                    new TimestampCandidate(
                            getStringAttribute(userCredentialsItem, "Created"),
                            "UserCredentials.Created"));
            candidates.add(
                    new TimestampCandidate(
                            getStringAttribute(userCredentialsItem, "Updated"),
                            "UserCredentials.Updated"));
        }

        return candidates;
    }

    private record TimestampCandidate(String timestamp, String source) {}

    public static String calculateDateForDeletion(String lastActiveDate) {
        if (lastActiveDate == null || lastActiveDate.isBlank()) {
            return null;
        }
        return LocalDateTime.parse(lastActiveDate).toLocalDate().plusYears(5).toString();
    }

    public static InactiveAccountTrackerItem buildTrackerItem(
            Map<String, AttributeValue> userProfileItem,
            Map<String, AttributeValue> userCredentialsItem) {
        String subjectId = getStringAttribute(userProfileItem, "SubjectID");
        String publicSubjectId = getStringAttribute(userProfileItem, "PublicSubjectID");
        String email = getStringAttribute(userProfileItem, "Email");

        LastActiveDate lastActiveDate =
                calculateLastActiveDate(userProfileItem, userCredentialsItem);
        String lastActiveTimestamp = lastActiveDate != null ? lastActiveDate.timestamp() : null;
        String lastActiveSource = lastActiveDate != null ? lastActiveDate.source() : null;

        String dateForDeletion = calculateDateForDeletion(lastActiveTimestamp);

        if (dateForDeletion == null) {
            LOG.warn(
                    "Skipping tracker item for public subject ID '{}': could not determine dateForDeletion (lastActiveDate was null)",
                    publicSubjectId);
            return null;
        }

        return new InactiveAccountTrackerItem()
                .withDateForDeletion(dateForDeletion)
                .withCommonSubjectId(subjectId)
                .withPublicSubjectId(publicSubjectId)
                .withEmailAddress(email)
                .withUserLastActive(lastActiveTimestamp)
                .withStatusLastUpdated(NowHelper.toTimestampString(NowHelper.now()))
                .withSourceId(lastActiveSource);
    }

    private static String getTermsAndConditionsTimestamp(Map<String, AttributeValue> item) {
        AttributeValue tcMap = item.get("termsAndConditions");
        if (tcMap == null || !tcMap.hasM()) {
            return null;
        }
        return getStringAttribute(tcMap.m(), "timestamp");
    }

    private static String getStringAttribute(
            Map<String, AttributeValue> item, String attributeName) {
        AttributeValue value = item.get(attributeName);
        return value != null ? value.s() : null;
    }
}
