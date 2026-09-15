package uk.gov.di.authentication.utils.helpers;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;
import uk.gov.di.authentication.shared.entity.UserProfile;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.utils.helpers.LastSignedInBackfillHelper.buildConditionalUpdateRequest;
import static uk.gov.di.authentication.utils.helpers.LastSignedInBackfillHelper.extractValidFields;

class LastSignedInBackfillHelperTest {

    private static final String USER_PROFILE_TABLE = "test-user-profile";
    private static final String TEST_EMAIL = "user@example.com";

    @Test
    void shouldSetCorrectTableName() {
        UpdateItemRequest request =
                buildConditionalUpdateRequest(
                        USER_PROFILE_TABLE, TEST_EMAIL, "2026-01-01T00:00:00.000Z");
        assertEquals(USER_PROFILE_TABLE, request.tableName());
    }

    @Test
    void shouldSetEmailAsPartitionKey() {
        UpdateItemRequest request =
                buildConditionalUpdateRequest(
                        USER_PROFILE_TABLE, TEST_EMAIL, "2026-01-01T00:00:00.000Z");
        assertEquals(TEST_EMAIL, request.key().get(UserProfile.ATTRIBUTE_EMAIL).s());
    }

    @Test
    void shouldSetCorrectUpdateExpression() {
        UpdateItemRequest request =
                buildConditionalUpdateRequest(
                        USER_PROFILE_TABLE, TEST_EMAIL, "2026-01-01T00:00:00.000Z");
        assertEquals("SET #lastSignedIn = :trackerTimestamp", request.updateExpression());
    }

    @Test
    void shouldSetCorrectConditionExpression() {
        UpdateItemRequest request =
                buildConditionalUpdateRequest(
                        USER_PROFILE_TABLE, TEST_EMAIL, "2026-01-01T00:00:00.000Z");
        assertEquals(
                "attribute_exists(#subjectId) AND (attribute_not_exists(#lastSignedIn) OR #lastSignedIn < :trackerTimestamp)",
                request.conditionExpression());
    }

    @Test
    void shouldMapSubjectIdAttributeName() {
        UpdateItemRequest request =
                buildConditionalUpdateRequest(
                        USER_PROFILE_TABLE, TEST_EMAIL, "2026-01-01T00:00:00.000Z");
        assertEquals(
                UserProfile.ATTRIBUTE_SUBJECT_ID,
                request.expressionAttributeNames().get("#subjectId"));
    }

    @Test
    void shouldMapLastSignedInAttributeName() {
        UpdateItemRequest request =
                buildConditionalUpdateRequest(
                        USER_PROFILE_TABLE, TEST_EMAIL, "2026-01-01T00:00:00.000Z");
        assertEquals(
                UserProfile.ATTRIBUTE_LAST_SIGNED_IN,
                request.expressionAttributeNames().get("#lastSignedIn"));
    }

    @Test
    void shouldSetTrackerTimestampValue() {
        String timestamp = "2026-01-01T00:00:00.000Z";
        UpdateItemRequest request =
                buildConditionalUpdateRequest(USER_PROFILE_TABLE, TEST_EMAIL, timestamp);
        assertEquals(timestamp, request.expressionAttributeValues().get(":trackerTimestamp").s());
    }

    @Test
    void shouldPreserveTimestampFormatAsIs() {
        // Value written as-is — no format conversion. Preserving the original string
        // ensures the DynamoDB lexicographic comparison in the condition expression works
        // correctly against the existing LastSignedIn value.
        String microsecondFormat = "2024-06-20T10:03:04.567890Z";
        UpdateItemRequest request =
                buildConditionalUpdateRequest(USER_PROFILE_TABLE, TEST_EMAIL, microsecondFormat);
        assertEquals(
                microsecondFormat,
                request.expressionAttributeValues().get(":trackerTimestamp").s());
    }

    @Test
    void shouldPreserveNoZSuffixFormatAsIs() {
        // Auth-backfilled tracker items use NowHelper.toTimestampString() which has no Z suffix.
        // The DynamoDB condition expression handles both formats correctly via lexicographic
        // comparison since both LastSignedIn and userLastActive are consistently UTC.
        String noZFormat = "2024-06-20T10:03:04.567890";
        UpdateItemRequest request =
                buildConditionalUpdateRequest(USER_PROFILE_TABLE, TEST_EMAIL, noZFormat);
        assertEquals(noZFormat, request.expressionAttributeValues().get(":trackerTimestamp").s());
    }

    @Test
    void trackerProjectionShouldContainBothAttributeNames() {
        assertTrue(
                LastSignedInBackfillHelper.TRACKER_PROJECTION.contains(
                        LastSignedInBackfillHelper.TRACKER_ATTRIBUTE_EMAIL));
        assertTrue(
                LastSignedInBackfillHelper.TRACKER_PROJECTION.contains(
                        LastSignedInBackfillHelper.TRACKER_ATTRIBUTE_USER_LAST_ACTIVE));
    }

    @Test
    void extractValidFieldsShouldReturnFieldsWhenBothPresent() {
        var item =
                Map.of(
                        LastSignedInBackfillHelper.TRACKER_ATTRIBUTE_EMAIL,
                        AttributeValue.fromS("user@example.com"),
                        LastSignedInBackfillHelper.TRACKER_ATTRIBUTE_USER_LAST_ACTIVE,
                        AttributeValue.fromS("2026-01-01T00:00:00.000Z"));

        var result = extractValidFields(item);

        assertTrue(result.isPresent());
        assertEquals("user@example.com", result.get().email());
        assertEquals("2026-01-01T00:00:00.000Z", result.get().userLastActive());
    }

    @Test
    void extractValidFieldsShouldReturnEmptyWhenEmailMissing() {
        var item =
                Map.of(
                        LastSignedInBackfillHelper.TRACKER_ATTRIBUTE_USER_LAST_ACTIVE,
                        AttributeValue.fromS("2026-01-01T00:00:00.000Z"));

        assertFalse(extractValidFields(item).isPresent());
    }

    @Test
    void extractValidFieldsShouldReturnEmptyWhenUserLastActiveMissing() {
        var item =
                Map.of(
                        LastSignedInBackfillHelper.TRACKER_ATTRIBUTE_EMAIL,
                        AttributeValue.fromS("user@example.com"));

        assertFalse(extractValidFields(item).isPresent());
    }

    @Test
    void extractValidFieldsShouldReturnEmptyWhenUserLastActiveIsBlank() {
        var item =
                Map.of(
                        LastSignedInBackfillHelper.TRACKER_ATTRIBUTE_EMAIL,
                        AttributeValue.fromS("user@example.com"),
                        LastSignedInBackfillHelper.TRACKER_ATTRIBUTE_USER_LAST_ACTIVE,
                        AttributeValue.fromS("   "));

        assertFalse(extractValidFields(item).isPresent());
    }
}
