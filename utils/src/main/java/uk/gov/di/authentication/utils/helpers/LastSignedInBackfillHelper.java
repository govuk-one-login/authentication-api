package uk.gov.di.authentication.utils.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;
import uk.gov.di.authentication.shared.entity.UserProfile;

import java.util.Map;
import java.util.Optional;

public class LastSignedInBackfillHelper {

    private static final Logger LOG = LogManager.getLogger(LastSignedInBackfillHelper.class);

    private static final String LOG_FIELD_ABSENT = "absent";
    private static final String LOG_FIELD_PRESENT = "present";

    public static final String TRACKER_ATTRIBUTE_EMAIL = "emailAddress";
    public static final String TRACKER_ATTRIBUTE_USER_LAST_ACTIVE = "userLastActive";
    public static final String TRACKER_ATTRIBUTE_PUBLIC_SUBJECT_ID = "publicSubjectId";

    public static final String TRACKER_PROJECTION =
            TRACKER_ATTRIBUTE_EMAIL
                    + ","
                    + TRACKER_ATTRIBUTE_USER_LAST_ACTIVE
                    + ","
                    + TRACKER_ATTRIBUTE_PUBLIC_SUBJECT_ID;

    private LastSignedInBackfillHelper() {}

    public static Optional<TrackerFields> extractValidFields(Map<String, AttributeValue> item) {
        AttributeValue emailAttr = item.get(TRACKER_ATTRIBUTE_EMAIL);
        AttributeValue userLastActiveAttr = item.get(TRACKER_ATTRIBUTE_USER_LAST_ACTIVE);
        AttributeValue publicSubjectIdAttr = item.get(TRACKER_ATTRIBUTE_PUBLIC_SUBJECT_ID);

        if (emailAttr == null
                || emailAttr.s() == null
                || emailAttr.s().isBlank()
                || userLastActiveAttr == null
                || userLastActiveAttr.s() == null
                || userLastActiveAttr.s().isBlank()) {
            return Optional.empty();
        }

        String publicSubjectId =
                publicSubjectIdAttr != null && publicSubjectIdAttr.s() != null
                        ? publicSubjectIdAttr.s()
                        : null;

        return Optional.of(
                new TrackerFields(emailAttr.s(), userLastActiveAttr.s(), publicSubjectId));
    }

    public static void logInvalidTrackerFields(Map<String, AttributeValue> item) {
        AttributeValue publicSubjectIdAttr = item.get(TRACKER_ATTRIBUTE_PUBLIC_SUBJECT_ID);
        String publicSubjectId =
                publicSubjectIdAttr != null && publicSubjectIdAttr.s() != null
                        ? publicSubjectIdAttr.s()
                        : LOG_FIELD_ABSENT;
        LOG.warn(
                "Skipping tracker item due to missing or blank required fields:"
                        + " email={}, userLastActive={}, publicSubjectId={}",
                item.containsKey(TRACKER_ATTRIBUTE_EMAIL) ? LOG_FIELD_PRESENT : LOG_FIELD_ABSENT,
                item.containsKey(TRACKER_ATTRIBUTE_USER_LAST_ACTIVE)
                        ? LOG_FIELD_PRESENT
                        : LOG_FIELD_ABSENT,
                publicSubjectId);
    }

    public static UpdateItemRequest buildConditionalUpdateRequest(
            String userProfileTableName, String email, String newLastSignedIn) {
        return UpdateItemRequest.builder()
                .tableName(userProfileTableName)
                .key(Map.of(UserProfile.ATTRIBUTE_EMAIL, AttributeValue.fromS(email)))
                .updateExpression("SET #lastSignedIn = :trackerTimestamp")
                .conditionExpression(
                        "attribute_exists(#subjectId) AND (attribute_not_exists(#lastSignedIn) OR #lastSignedIn < :trackerTimestamp)")
                .expressionAttributeNames(
                        Map.of(
                                "#lastSignedIn",
                                UserProfile.ATTRIBUTE_LAST_SIGNED_IN,
                                "#subjectId",
                                UserProfile.ATTRIBUTE_SUBJECT_ID))
                .expressionAttributeValues(
                        Map.of(":trackerTimestamp", AttributeValue.fromS(newLastSignedIn)))
                .build();
    }

    public record TrackerFields(String email, String userLastActive, String publicSubjectId) {}
}
