package uk.gov.di.authentication.utils.helpers;

import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;
import uk.gov.di.authentication.shared.entity.UserProfile;

import java.util.Map;
import java.util.Optional;

public class LastSignedInBackfillHelper {

    public static final String TRACKER_ATTRIBUTE_EMAIL = "emailAddress";
    public static final String TRACKER_ATTRIBUTE_USER_LAST_ACTIVE = "userLastActive";

    public static final String TRACKER_PROJECTION =
            TRACKER_ATTRIBUTE_EMAIL + "," + TRACKER_ATTRIBUTE_USER_LAST_ACTIVE;

    private LastSignedInBackfillHelper() {}

    /**
     * Extracts the email and userLastActive values from a tracker item. Returns empty if either
     * field is absent, null, or blank — indicating the item should be skipped.
     */
    public static Optional<TrackerFields> extractValidFields(Map<String, AttributeValue> item) {
        AttributeValue emailAttr = item.get(TRACKER_ATTRIBUTE_EMAIL);
        AttributeValue userLastActiveAttr = item.get(TRACKER_ATTRIBUTE_USER_LAST_ACTIVE);

        if (emailAttr == null
                || emailAttr.s() == null
                || userLastActiveAttr == null
                || userLastActiveAttr.s() == null
                || userLastActiveAttr.s().isBlank()) {
            return Optional.empty();
        }

        return Optional.of(new TrackerFields(emailAttr.s(), userLastActiveAttr.s()));
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

    public record TrackerFields(String email, String userLastActive) {}
}
