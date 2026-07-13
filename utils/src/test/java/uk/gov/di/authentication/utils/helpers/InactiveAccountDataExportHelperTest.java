package uk.gov.di.authentication.utils.helpers;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.KeysAndAttributes;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.buildCredentialKeys;
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
}
