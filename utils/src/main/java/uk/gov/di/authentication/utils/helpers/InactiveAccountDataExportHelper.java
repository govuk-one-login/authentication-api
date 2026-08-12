package uk.gov.di.authentication.utils.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.KeysAndAttributes;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
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
                            getStringAttribute(userProfileItem, UserProfile.ATTRIBUTE_CREATED),
                            "UserProfile.Created"));
            candidates.add(
                    new TimestampCandidate(
                            getStringAttribute(userProfileItem, UserProfile.ATTRIBUTE_UPDATED),
                            "UserProfile.Updated"));
            candidates.add(
                    new TimestampCandidate(
                            getTermsAndConditionsTimestamp(userProfileItem),
                            "UserProfile.termsAndConditions.timestamp"));
        }

        if (userCredentialsItem != null) {
            candidates.add(
                    new TimestampCandidate(
                            getStringAttribute(
                                    userCredentialsItem, UserCredentials.ATTRIBUTE_CREATED),
                            "UserCredentials.Created"));
            candidates.add(
                    new TimestampCandidate(
                            getStringAttribute(
                                    userCredentialsItem, UserCredentials.ATTRIBUTE_UPDATED),
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

    public static void ensureSaltPresent(
            Map<String, AttributeValue> userProfileItem,
            DynamoDbClient dynamoDbClient,
            String userProfileTableName) {
        AttributeValue saltAttr = userProfileItem.get(UserProfile.ATTRIBUTE_SALT);
        if (saltAttr != null && saltAttr.b() != null && saltAttr.b().asByteArray().length > 0) {
            return;
        }

        String email = getStringAttribute(userProfileItem, UserProfile.ATTRIBUTE_EMAIL);
        LOG.info("Generating salt for email '{}': salt was missing or empty", email);

        byte[] newSalt = SaltHelper.generateNewSalt();
        dynamoDbClient.updateItem(
                UpdateItemRequest.builder()
                        .tableName(userProfileTableName)
                        .key(Map.of(UserProfile.ATTRIBUTE_EMAIL, AttributeValue.fromS(email)))
                        .updateExpression("SET #salt = :salt")
                        .expressionAttributeNames(Map.of("#salt", UserProfile.ATTRIBUTE_SALT))
                        .expressionAttributeValues(
                                Map.of(
                                        ":salt",
                                        AttributeValue.fromB(SdkBytes.fromByteArray(newSalt))))
                        .build());

        userProfileItem.put(
                UserProfile.ATTRIBUTE_SALT, AttributeValue.fromB(SdkBytes.fromByteArray(newSalt)));
    }

    public static InactiveAccountTrackerItem buildTrackerItem(
            Map<String, AttributeValue> userProfileItem,
            Map<String, AttributeValue> userCredentialsItem) {
        String subjectId = getStringAttribute(userProfileItem, UserProfile.ATTRIBUTE_SUBJECT_ID);
        String publicSubjectId =
                getStringAttribute(userProfileItem, UserProfile.ATTRIBUTE_PUBLIC_SUBJECT_ID);
        String email = getStringAttribute(userProfileItem, UserProfile.ATTRIBUTE_EMAIL);

        LastActiveDate lastActiveDate =
                calculateLastActiveDate(userProfileItem, userCredentialsItem);
        String lastActiveTimestamp = lastActiveDate != null ? lastActiveDate.timestamp() : null;
        String lastActiveSourceId = lastActiveDate != null ? lastActiveDate.source() : null;

        String dateForDeletion = calculateDateForDeletion(lastActiveTimestamp);

        if (dateForDeletion == null) {
            LOG.warn(
                    "Skipping tracker item for public subject ID '{}': could not determine dateForDeletion (lastActiveDate was null)",
                    publicSubjectId);
            return null;
        }

        var currentTimestamp = NowHelper.toTimestampString(NowHelper.now());
        String profileUpdated = getStringAttribute(userProfileItem, UserProfile.ATTRIBUTE_UPDATED);

        return new InactiveAccountTrackerItem()
                .withDateForDeletion(dateForDeletion)
                .withCommonSubjectId(subjectId)
                .withPublicSubjectId(publicSubjectId)
                .withEmailAddress(email)
                .withEmailAddressLastUpdated(profileUpdated)
                .withStatusLastUpdated(currentTimestamp)
                .withUserLastActive(lastActiveTimestamp)
                .withUserLastActiveSourceId(lastActiveSourceId)
                .withUserLastActiveUpdated(currentTimestamp)
                .withHasSetupMfa(determineHasSetupMfa(userProfileItem, userCredentialsItem));
    }

    public static boolean determineHasSetupMfa(
            Map<String, AttributeValue> userProfileItem,
            Map<String, AttributeValue> userCredentialsItem) {
        AttributeValue migratedAttr =
                userProfileItem.get(UserProfile.ATTRIBUTE_MFA_METHODS_MIGRATED);
        boolean isMigrated = migratedAttr != null && Boolean.TRUE.equals(migratedAttr.bool());

        if (isMigrated) {
            return hasMfaMethods(userCredentialsItem);
        }

        AttributeValue phoneVerifiedAttr =
                userProfileItem.get(UserProfile.ATTRIBUTE_PHONE_NUMBER_VERIFIED);
        boolean phoneVerified = phoneVerifiedAttr != null && "1".equals(phoneVerifiedAttr.n());

        if (phoneVerified) {
            return true;
        }

        return hasMfaMethods(userCredentialsItem);
    }

    private static boolean hasMfaMethods(Map<String, AttributeValue> userCredentialsItem) {
        if (userCredentialsItem == null) {
            return false;
        }
        AttributeValue mfaMethodsAttr =
                userCredentialsItem.get(UserCredentials.ATTRIBUTE_MFA_METHODS);
        if (mfaMethodsAttr == null || !mfaMethodsAttr.hasL()) {
            return false;
        }
        return !mfaMethodsAttr.l().isEmpty();
    }

    private static String getTermsAndConditionsTimestamp(Map<String, AttributeValue> item) {
        AttributeValue tcMap = item.get(UserProfile.ATTRIBUTE_TERMS_AND_CONDITIONS);
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
