package uk.gov.di.authentication.utils.helpers;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.KeysAndAttributes;
import uk.gov.di.authentication.utils.entity.InactiveAccountTrackerItem;
import uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.LastActiveDate;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.buildCredentialKeys;
import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.buildTrackerItem;
import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.calculateDateForDeletion;
import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.calculateLastActiveDate;
import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.countMissingCredentials;
import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.extractUnprocessedKeys;

class InactiveAccountDataExportHelperTest {

    private static final String TABLE_NAME = "test-user-credentials";

    @Test
    void buildCredentialKeysShouldExtractEmailKeysFromProfileItems() {
        List<Map<String, AttributeValue>> profileItems =
                List.of(
                        Map.of("Email", AttributeValue.builder().s("a@example.com").build()),
                        Map.of("Email", AttributeValue.builder().s("b@example.com").build()),
                        Map.of("Email", AttributeValue.builder().s("c@example.com").build()));

        var keys = buildCredentialKeys(profileItems);

        assertEquals(3, keys.size());
        assertEquals("a@example.com", keys.get(0).get("Email").s());
        assertEquals("b@example.com", keys.get(1).get("Email").s());
        assertEquals("c@example.com", keys.get(2).get("Email").s());
    }

    @Test
    void buildCredentialKeysShouldReturnEmptyListForEmptyInput() {
        var keys = buildCredentialKeys(List.of());

        assertTrue(keys.isEmpty());
    }

    @Test
    void extractUnprocessedKeysShouldReturnEmptyMapWhenNoUnprocessedKeys() {
        var response =
                BatchGetItemResponse.builder().responses(Map.of(TABLE_NAME, List.of())).build();

        var result = extractUnprocessedKeys(response, TABLE_NAME);

        assertTrue(result.isEmpty());
    }

    @Test
    void extractUnprocessedKeysShouldReturnEmptyMapWhenTableNotInUnprocessed() {
        var response =
                BatchGetItemResponse.builder()
                        .responses(Map.of(TABLE_NAME, List.of()))
                        .unprocessedKeys(
                                Map.of(
                                        "other-table",
                                        KeysAndAttributes.builder()
                                                .keys(
                                                        List.of(
                                                                Map.of(
                                                                        "Email",
                                                                        AttributeValue.builder()
                                                                                .s("x@example.com")
                                                                                .build())))
                                                .build()))
                        .build();

        var result = extractUnprocessedKeys(response, TABLE_NAME);

        assertTrue(result.isEmpty());
    }

    @Test
    void extractUnprocessedKeysShouldReturnKeysWhenPresent() {
        List<Map<String, AttributeValue>> unprocessed =
                List.of(
                        Map.of("Email", AttributeValue.builder().s("a@example.com").build()),
                        Map.of("Email", AttributeValue.builder().s("b@example.com").build()));

        var response =
                BatchGetItemResponse.builder()
                        .responses(Map.of(TABLE_NAME, List.of()))
                        .unprocessedKeys(
                                Map.of(
                                        TABLE_NAME,
                                        KeysAndAttributes.builder().keys(unprocessed).build()))
                        .build();

        var result = extractUnprocessedKeys(response, TABLE_NAME);

        assertEquals(2, result.get(TABLE_NAME).keys().size());
    }

    @Test
    void countMissingCredentialsShouldReturnZeroWhenAllReturned() {
        assertEquals(0, countMissingCredentials(5, 5));
    }

    @Test
    void countMissingCredentialsShouldReturnDifferenceWhenSomeMissing() {
        assertEquals(3, countMissingCredentials(10, 7));
    }

    @Test
    void countMissingCredentialsShouldReturnZeroWhenReturnedExceedsRequested() {
        assertEquals(0, countMissingCredentials(3, 5));
    }

    @Test
    void countMissingCredentialsShouldReturnRequestedCountWhenNoneReturned() {
        assertEquals(5, countMissingCredentials(5, 0));
    }

    @Test
    void countMissingCredentialsShouldReturnZeroForZeroInputs() {
        assertEquals(0, countMissingCredentials(0, 0));
    }

    @Test
    void buildTrackerItemShouldMapAllFieldsFromUserProfileItem() {
        Map<String, AttributeValue> userProfileItem =
                Map.of(
                        "SubjectID",
                        AttributeValue.builder().s("subject-123").build(),
                        "PublicSubjectID",
                        AttributeValue.builder().s("public-456").build(),
                        "Email",
                        AttributeValue.builder().s("test@example.com").build(),
                        "Updated",
                        AttributeValue.builder().s("2021-07-17T10:30:00.000000").build());

        Map<String, AttributeValue> userCredentialsItem =
                Map.of("Email", AttributeValue.builder().s("test@example.com").build());

        InactiveAccountTrackerItem result = buildTrackerItem(userProfileItem, userCredentialsItem);

        assertEquals("2026-07-17", result.getDateForDeletion());
        assertEquals("subject-123", result.getCommonSubjectId());
        assertEquals("public-456", result.getPublicSubjectId());
        assertEquals("test@example.com", result.getEmailAddress());
        assertEquals("2021-07-17T10:30:00.000000", result.getUserLastActive());
        assertEquals("pending", result.getStatus());
        assertEquals("AUTH_BACKFILL", result.getSource());
        assertEquals("user_profile.updated", result.getSourceId());
        assertNotNull(result.getStatusLastUpdated());
    }

    @Test
    void buildTrackerItemShouldHandleMissingUpdatedAttribute() {
        Map<String, AttributeValue> userProfileItem =
                Map.of("SubjectID", AttributeValue.builder().s("subject-789").build());

        InactiveAccountTrackerItem result = buildTrackerItem(userProfileItem, null);

        assertNull(result.getDateForDeletion());
        assertEquals("subject-789", result.getCommonSubjectId());
        assertNull(result.getPublicSubjectId());
        assertNull(result.getEmailAddress());
        assertNull(result.getUserLastActive());
        assertNull(result.getSourceId());
        assertNotNull(result.getStatusLastUpdated());
    }

    @Test
    void buildTrackerItemShouldSetSourceIdToSubjectId() {
        Map<String, AttributeValue> userProfileItem =
                Map.of(
                        "SubjectID",
                        AttributeValue.builder().s("my-subject-id").build(),
                        "Email",
                        AttributeValue.builder().s("user@gov.uk").build(),
                        "Updated",
                        AttributeValue.builder().s("2020-01-01T00:00:00.000000").build());

        InactiveAccountTrackerItem result = buildTrackerItem(userProfileItem, null);

        assertEquals("user_profile.updated", result.getSourceId());
        assertEquals("my-subject-id", result.getCommonSubjectId());
    }

    @Test
    void calculateLastActiveDateShouldReturnUpdatedFromUserProfile() {
        Map<String, AttributeValue> userProfileItem =
                Map.of("Updated", AttributeValue.builder().s("2023-05-10T14:30:00.000000").build());

        LastActiveDate result = calculateLastActiveDate(userProfileItem, null);

        assertEquals("2023-05-10T14:30:00.000000", result.timestamp());
        assertEquals("user_profile.updated", result.source());
    }

    @Test
    void calculateLastActiveDateShouldReturnNullWhenUpdatedMissing() {
        Map<String, AttributeValue> userProfileItem =
                Map.of("Email", AttributeValue.builder().s("test@example.com").build());

        LastActiveDate result = calculateLastActiveDate(userProfileItem, null);

        assertNull(result);
    }

    @Test
    void calculateDateForDeletionShouldAddFiveYearsToDate() {
        assertEquals("2029-03-15", calculateDateForDeletion("2024-03-15T10:30:00.000000"));
    }

    @Test
    void calculateDateForDeletionShouldReturnNullForNullInput() {
        assertNull(calculateDateForDeletion(null));
    }

    @Test
    void calculateDateForDeletionShouldReturnNullForBlankInput() {
        assertNull(calculateDateForDeletion(""));
    }
}
