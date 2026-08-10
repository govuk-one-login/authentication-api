package uk.gov.di.authentication.utils.helpers;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.KeysAndAttributes;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.utils.entity.InactiveAccountTrackerItem;
import uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.LastActiveDate;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.buildCredentialKeys;
import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.buildTrackerItem;
import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.calculateDateForDeletion;
import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.calculateLastActiveDate;
import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.countMissingCredentials;
import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.determineHasSetupMfa;
import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.ensureSaltPresent;
import static uk.gov.di.authentication.utils.helpers.InactiveAccountDataExportHelper.extractUnprocessedKeys;

class InactiveAccountDataExportHelperTest {

    private static final String TABLE_NAME = "test-user-credentials";
    private static final String USER_PROFILE_TABLE_NAME = "test-user-profile";
    private static final String INTERNAL_SECTOR_URI = "https://identity.test.account.gov.uk";
    private final DynamoDbClient dynamoDbClient = mock(DynamoDbClient.class);

    @Test
    void buildCredentialKeysShouldExtractEmailKeysFromProfileItems() {
        List<Map<String, AttributeValue>> profileItems =
                List.of(
                        Map.of(
                                UserCredentials.ATTRIBUTE_EMAIL,
                                AttributeValue.builder().s("a@example.com").build()),
                        Map.of(
                                UserCredentials.ATTRIBUTE_EMAIL,
                                AttributeValue.builder().s("b@example.com").build()),
                        Map.of(
                                UserCredentials.ATTRIBUTE_EMAIL,
                                AttributeValue.builder().s("c@example.com").build()));

        var keys = buildCredentialKeys(profileItems);

        assertEquals(3, keys.size());
        assertEquals("a@example.com", keys.get(0).get(UserCredentials.ATTRIBUTE_EMAIL).s());
        assertEquals("b@example.com", keys.get(1).get(UserCredentials.ATTRIBUTE_EMAIL).s());
        assertEquals("c@example.com", keys.get(2).get(UserCredentials.ATTRIBUTE_EMAIL).s());
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
                                                                        UserCredentials
                                                                                .ATTRIBUTE_EMAIL,
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
                        Map.of(
                                UserCredentials.ATTRIBUTE_EMAIL,
                                AttributeValue.builder().s("a@example.com").build()),
                        Map.of(
                                UserCredentials.ATTRIBUTE_EMAIL,
                                AttributeValue.builder().s("b@example.com").build()));

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

    @Nested
    class EnsureSaltPresentTest {

        @Test
        void shouldReturnWithoutCallingDynamoWhenSaltAlreadyExists() {
            Map<String, AttributeValue> profileItem =
                    Map.of(
                            UserProfile.ATTRIBUTE_EMAIL,
                            AttributeValue.builder().s("test@example.com").build(),
                            UserProfile.ATTRIBUTE_SALT,
                            AttributeValue.builder()
                                    .b(SdkBytes.fromByteArray(new byte[] {1, 2, 3}))
                                    .build());

            ensureSaltPresent(profileItem, dynamoDbClient, USER_PROFILE_TABLE_NAME);

            verify(dynamoDbClient, never()).updateItem(any(UpdateItemRequest.class));
        }

        @Test
        void shouldGenerateAndPersistSaltWhenMissing() {
            Map<String, AttributeValue> profileItem = new HashMap<>();
            profileItem.put(
                    UserProfile.ATTRIBUTE_EMAIL,
                    AttributeValue.builder().s("nosalt@example.com").build());

            ensureSaltPresent(profileItem, dynamoDbClient, USER_PROFILE_TABLE_NAME);

            verify(dynamoDbClient).updateItem(any(UpdateItemRequest.class));
            assertNotNull(profileItem.get(UserProfile.ATTRIBUTE_SALT));
            assertTrue(profileItem.get(UserProfile.ATTRIBUTE_SALT).b().asByteArray().length > 0);
        }

        @Test
        void shouldGenerateAndPersistSaltWhenEmpty() {
            Map<String, AttributeValue> profileItem = new HashMap<>();
            profileItem.put(
                    UserProfile.ATTRIBUTE_EMAIL,
                    AttributeValue.builder().s("emptysalt@example.com").build());
            profileItem.put(
                    UserProfile.ATTRIBUTE_SALT,
                    AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[] {})).build());

            ensureSaltPresent(profileItem, dynamoDbClient, USER_PROFILE_TABLE_NAME);

            verify(dynamoDbClient).updateItem(any(UpdateItemRequest.class));
            assertTrue(profileItem.get(UserProfile.ATTRIBUTE_SALT).b().asByteArray().length > 0);
        }
    }

    @Test
    void buildTrackerItemShouldMapAllFieldsFromUserProfileItem() {
        Map<String, AttributeValue> userProfileItem =
                Map.of(
                        UserProfile.ATTRIBUTE_SUBJECT_ID,
                        AttributeValue.builder().s("subject-123").build(),
                        UserProfile.ATTRIBUTE_PUBLIC_SUBJECT_ID,
                        AttributeValue.builder().s("public-456").build(),
                        UserProfile.ATTRIBUTE_EMAIL,
                        AttributeValue.builder().s("test@example.com").build(),
                        UserProfile.ATTRIBUTE_UPDATED,
                        AttributeValue.builder().s("2021-07-17T10:30:00.123456").build(),
                        UserProfile.ATTRIBUTE_SALT,
                        AttributeValue.builder()
                                .b(SdkBytes.fromByteArray(new byte[] {1, 2, 3, 4, 5}))
                                .build());

        Map<String, AttributeValue> userCredentialsItem =
                Map.of(
                        UserCredentials.ATTRIBUTE_EMAIL,
                        AttributeValue.builder().s("test@example.com").build());

        InactiveAccountTrackerItem result =
                buildTrackerItem(userProfileItem, userCredentialsItem, INTERNAL_SECTOR_URI);

        assertEquals("2026-07-17", result.getDateForDeletion());
        assertTrue(result.getCommonSubjectId().startsWith("urn:fdc:gov.uk:2022:"));
        assertEquals("public-456", result.getPublicSubjectId());
        assertEquals("test@example.com", result.getEmailAddress());
        assertEquals("2021-07-17T10:30:00.123456", result.getEmailAddressLastUpdated());
        assertEquals("AUTH_BACKFILL", result.getEmailAddressSource());
        assertEquals("UserProfile.Email", result.getEmailAddressSourceId());
        assertEquals("2021-07-17T10:30:00.123456", result.getUserLastActive());
        assertEquals("pending", result.getStatus());
        assertEquals("AUTH_BACKFILL", result.getUserLastActiveSource());
        assertEquals("UserProfile.Updated", result.getUserLastActiveSourceId());
        assertNotNull(result.getStatusLastUpdated());
        assertNotNull(result.getUserLastActiveUpdated());
        assertFalse(result.getHasSetupMfa());
    }

    @Test
    void buildTrackerItemShouldReturnNullWhenNoTimestampsAvailable() {
        Map<String, AttributeValue> userProfileItem =
                Map.of(
                        UserProfile.ATTRIBUTE_SUBJECT_ID,
                        AttributeValue.builder().s("subject-789").build(),
                        UserProfile.ATTRIBUTE_SALT,
                        AttributeValue.builder()
                                .b(SdkBytes.fromByteArray(new byte[] {1, 2, 3}))
                                .build());

        InactiveAccountTrackerItem result =
                buildTrackerItem(userProfileItem, null, INTERNAL_SECTOR_URI);

        assertNull(result);
    }

    @Test
    void buildTrackerItemShouldSetSourceIdToSubjectId() {
        Map<String, AttributeValue> userProfileItem =
                Map.of(
                        UserProfile.ATTRIBUTE_SUBJECT_ID,
                        AttributeValue.builder().s("my-subject-id").build(),
                        UserProfile.ATTRIBUTE_EMAIL,
                        AttributeValue.builder().s("user@gov.uk").build(),
                        UserProfile.ATTRIBUTE_UPDATED,
                        AttributeValue.builder().s("2020-01-01T00:00:00.000000").build(),
                        UserProfile.ATTRIBUTE_SALT,
                        AttributeValue.builder()
                                .b(SdkBytes.fromByteArray(new byte[] {10, 20, 30}))
                                .build());

        InactiveAccountTrackerItem result =
                buildTrackerItem(userProfileItem, null, INTERNAL_SECTOR_URI);

        assertEquals("UserProfile.Updated", result.getUserLastActiveSourceId());
        assertTrue(result.getCommonSubjectId().startsWith("urn:fdc:gov.uk:2022:"));
    }

    @Test
    void buildTrackerItemShouldReturnNullWhenSaltIsMissing() {
        Map<String, AttributeValue> userProfileItem =
                Map.of(
                        UserProfile.ATTRIBUTE_SUBJECT_ID,
                        AttributeValue.builder().s("subject-no-salt").build(),
                        UserProfile.ATTRIBUTE_PUBLIC_SUBJECT_ID,
                        AttributeValue.builder().s("public-no-salt").build(),
                        UserProfile.ATTRIBUTE_EMAIL,
                        AttributeValue.builder().s("nosalt@example.com").build(),
                        UserProfile.ATTRIBUTE_UPDATED,
                        AttributeValue.builder().s("2021-07-17T10:30:00.123456").build());

        InactiveAccountTrackerItem result =
                buildTrackerItem(userProfileItem, null, INTERNAL_SECTOR_URI);

        assertNull(result);
    }

    @Test
    void buildTrackerItemShouldReturnNullWhenSaltIsEmpty() {
        Map<String, AttributeValue> userProfileItem = new HashMap<>();
        userProfileItem.put(
                UserProfile.ATTRIBUTE_SUBJECT_ID,
                AttributeValue.builder().s("subject-empty-salt").build());
        userProfileItem.put(
                UserProfile.ATTRIBUTE_PUBLIC_SUBJECT_ID,
                AttributeValue.builder().s("public-empty-salt").build());
        userProfileItem.put(
                UserProfile.ATTRIBUTE_EMAIL,
                AttributeValue.builder().s("emptysalt@example.com").build());
        userProfileItem.put(
                UserProfile.ATTRIBUTE_UPDATED,
                AttributeValue.builder().s("2021-07-17T10:30:00.123456").build());
        userProfileItem.put(
                UserProfile.ATTRIBUTE_SALT,
                AttributeValue.builder().b(SdkBytes.fromByteArray(new byte[] {})).build());

        InactiveAccountTrackerItem result =
                buildTrackerItem(userProfileItem, null, INTERNAL_SECTOR_URI);

        assertNull(result);
    }

    @Test
    void buildTrackerItemShouldReturnNullWhenSubjectIdIsNull() {
        Map<String, AttributeValue> userProfileItem = new HashMap<>();
        userProfileItem.put(
                UserProfile.ATTRIBUTE_PUBLIC_SUBJECT_ID,
                AttributeValue.builder().s("public-no-subject").build());
        userProfileItem.put(
                UserProfile.ATTRIBUTE_EMAIL,
                AttributeValue.builder().s("nosubject@example.com").build());
        userProfileItem.put(
                UserProfile.ATTRIBUTE_UPDATED,
                AttributeValue.builder().s("2021-07-17T10:30:00.123456").build());
        userProfileItem.put(
                UserProfile.ATTRIBUTE_SALT,
                AttributeValue.builder()
                        .b(SdkBytes.fromByteArray(new byte[] {1, 2, 3, 4, 5}))
                        .build());

        InactiveAccountTrackerItem result =
                buildTrackerItem(userProfileItem, null, INTERNAL_SECTOR_URI);

        assertNull(result);
    }

    @Test
    void calculateLastActiveDateShouldReturnMostRecentAcrossAllAttributes() {
        Map<String, AttributeValue> userProfileItem =
                Map.of(
                        UserProfile.ATTRIBUTE_CREATED,
                        AttributeValue.builder().s("2022-01-01T10:00:00.111111").build(),
                        UserProfile.ATTRIBUTE_UPDATED,
                        AttributeValue.builder().s("2023-05-10T14:30:00.222222").build(),
                        UserProfile.ATTRIBUTE_TERMS_AND_CONDITIONS,
                        AttributeValue.builder()
                                .m(
                                        Map.of(
                                                "timestamp",
                                                AttributeValue.builder()
                                                        .s("2024-11-20T09:15:00.123456")
                                                        .build()))
                                .build());

        Map<String, AttributeValue> userCredentialsItem =
                Map.of(
                        UserCredentials.ATTRIBUTE_CREATED,
                        AttributeValue.builder().s("2022-01-01T10:00:00.111111").build(),
                        UserCredentials.ATTRIBUTE_UPDATED,
                        AttributeValue.builder().s("2024-06-01T08:00:00.333333").build());

        LastActiveDate result = calculateLastActiveDate(userProfileItem, userCredentialsItem);

        assertEquals("2024-11-20T09:15:00.123456", result.timestamp());
        assertEquals("UserProfile.termsAndConditions.timestamp", result.source());
    }

    @Test
    void calculateLastActiveDateShouldReturnCredentialsUpdatedWhenMostRecent() {
        Map<String, AttributeValue> userProfileItem =
                Map.of(
                        UserProfile.ATTRIBUTE_CREATED,
                        AttributeValue.builder().s("2020-01-01T00:00:00.111111").build(),
                        UserProfile.ATTRIBUTE_UPDATED,
                        AttributeValue.builder().s("2021-06-15T12:00:00.222222").build());

        Map<String, AttributeValue> userCredentialsItem =
                Map.of(
                        UserCredentials.ATTRIBUTE_CREATED,
                        AttributeValue.builder().s("2020-01-01T00:00:00.111111").build(),
                        UserCredentials.ATTRIBUTE_UPDATED,
                        AttributeValue.builder().s("2025-03-20T16:45:00.552352138").build());

        LastActiveDate result = calculateLastActiveDate(userProfileItem, userCredentialsItem);

        assertEquals("2025-03-20T16:45:00.552352138", result.timestamp());
        assertEquals("UserCredentials.Updated", result.source());
    }

    @Test
    void calculateLastActiveDateShouldReturnProfileCreatedWhenOnlyAttributePresent() {
        Map<String, AttributeValue> userProfileItem =
                Map.of(
                        UserProfile.ATTRIBUTE_CREATED,
                        AttributeValue.builder().s("2023-05-10T14:30:00.123456").build());

        LastActiveDate result = calculateLastActiveDate(userProfileItem, null);

        assertEquals("2023-05-10T14:30:00.123456", result.timestamp());
        assertEquals("UserProfile.Created", result.source());
    }

    @Test
    void calculateLastActiveDateShouldReturnNullWhenNoTimestampAttributesPresent() {
        Map<String, AttributeValue> userProfileItem =
                Map.of(
                        UserProfile.ATTRIBUTE_EMAIL,
                        AttributeValue.builder().s("test@example.com").build());

        LastActiveDate result = calculateLastActiveDate(userProfileItem, null);

        assertNull(result);
    }

    @Test
    void calculateLastActiveDateShouldReturnNullWhenBothItemsNull() {
        LastActiveDate result = calculateLastActiveDate(null, null);

        assertNull(result);
    }

    @Test
    void calculateLastActiveDateShouldHandleOnlyCredentialsItemProvided() {
        Map<String, AttributeValue> userCredentialsItem =
                Map.of(
                        UserCredentials.ATTRIBUTE_CREATED,
                        AttributeValue.builder().s("2022-08-01T09:00:00.111111").build(),
                        UserCredentials.ATTRIBUTE_UPDATED,
                        AttributeValue.builder().s("2023-12-25T18:30:00.654321").build());

        Map<String, AttributeValue> userProfileItem =
                Map.of(
                        UserProfile.ATTRIBUTE_EMAIL,
                        AttributeValue.builder().s("test@example.com").build());

        LastActiveDate result = calculateLastActiveDate(userProfileItem, userCredentialsItem);

        assertEquals("2023-12-25T18:30:00.654321", result.timestamp());
        assertEquals("UserCredentials.Updated", result.source());
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

    @Nested
    class DetermineHasSetupMfaTest {

        @Test
        void shouldReturnTrueForMigratedUserWithMfaMethods() {
            Map<String, AttributeValue> profileItem =
                    Map.of(
                            UserProfile.ATTRIBUTE_MFA_METHODS_MIGRATED,
                            AttributeValue.builder().bool(true).build());

            Map<String, AttributeValue> credentialsItem =
                    Map.of(
                            UserCredentials.ATTRIBUTE_MFA_METHODS,
                            AttributeValue.builder()
                                    .l(
                                            List.of(
                                                    AttributeValue.builder()
                                                            .m(
                                                                    Map.of(
                                                                            "MfaMethodType",
                                                                            AttributeValue.builder()
                                                                                    .s("AUTH_APP")
                                                                                    .build()))
                                                            .build()))
                                    .build());

            assertTrue(determineHasSetupMfa(profileItem, credentialsItem));
        }

        @Test
        void shouldReturnFalseForMigratedUserWithNoMfaMethods() {
            Map<String, AttributeValue> profileItem =
                    Map.of(
                            UserProfile.ATTRIBUTE_MFA_METHODS_MIGRATED,
                            AttributeValue.builder().bool(true).build());

            Map<String, AttributeValue> credentialsItem =
                    Map.of(
                            UserCredentials.ATTRIBUTE_EMAIL,
                            AttributeValue.builder().s("test@example.com").build());

            assertFalse(determineHasSetupMfa(profileItem, credentialsItem));
        }

        @Test
        void shouldReturnFalseForMigratedUserWithEmptyMfaMethodsList() {
            Map<String, AttributeValue> profileItem =
                    Map.of(
                            UserProfile.ATTRIBUTE_MFA_METHODS_MIGRATED,
                            AttributeValue.builder().bool(true).build());

            Map<String, AttributeValue> credentialsItem =
                    Map.of(
                            UserCredentials.ATTRIBUTE_MFA_METHODS,
                            AttributeValue.builder().l(List.of()).build());

            assertFalse(determineHasSetupMfa(profileItem, credentialsItem));
        }

        @Test
        void shouldReturnTrueForUnmigratedUserWithPhoneNumberVerified() {
            Map<String, AttributeValue> profileItem =
                    Map.of(
                            UserProfile.ATTRIBUTE_PHONE_NUMBER_VERIFIED,
                            AttributeValue.builder().n("1").build());

            Map<String, AttributeValue> credentialsItem =
                    Map.of(
                            UserCredentials.ATTRIBUTE_EMAIL,
                            AttributeValue.builder().s("test@example.com").build());

            assertTrue(determineHasSetupMfa(profileItem, credentialsItem));
        }

        @Test
        void shouldReturnTrueForUnmigratedUserWithMfaMethodPresent() {
            Map<String, AttributeValue> profileItem =
                    Map.of(
                            UserProfile.ATTRIBUTE_PHONE_NUMBER_VERIFIED,
                            AttributeValue.builder().n("0").build());

            Map<String, AttributeValue> credentialsItem =
                    Map.of(
                            UserCredentials.ATTRIBUTE_MFA_METHODS,
                            AttributeValue.builder()
                                    .l(
                                            List.of(
                                                    AttributeValue.builder()
                                                            .m(
                                                                    Map.of(
                                                                            "MfaMethodType",
                                                                            AttributeValue.builder()
                                                                                    .s("AUTH_APP")
                                                                                    .build()))
                                                            .build()))
                                    .build());

            assertTrue(determineHasSetupMfa(profileItem, credentialsItem));
        }

        @Test
        void shouldReturnFalseForUnmigratedUserWithPhoneNotVerifiedAndNoMfaMethods() {
            Map<String, AttributeValue> profileItem =
                    Map.of(
                            UserProfile.ATTRIBUTE_PHONE_NUMBER_VERIFIED,
                            AttributeValue.builder().n("0").build());

            Map<String, AttributeValue> credentialsItem =
                    Map.of(
                            UserCredentials.ATTRIBUTE_EMAIL,
                            AttributeValue.builder().s("test@example.com").build());

            assertFalse(determineHasSetupMfa(profileItem, credentialsItem));
        }

        @Test
        void shouldReturnFalseForUnmigratedUserWithPhoneNotVerifiedAndEmptyMfaMethods() {
            Map<String, AttributeValue> profileItem =
                    Map.of(
                            UserProfile.ATTRIBUTE_PHONE_NUMBER_VERIFIED,
                            AttributeValue.builder().n("0").build());

            Map<String, AttributeValue> credentialsItem =
                    Map.of(
                            UserCredentials.ATTRIBUTE_MFA_METHODS,
                            AttributeValue.builder().l(List.of()).build());

            assertFalse(determineHasSetupMfa(profileItem, credentialsItem));
        }
    }

    @Test
    void buildTrackerItemShouldExtractHostFromUriWhenCalculatingPairwiseIdentifier() {
        String subjectId = "test-subject-id";
        byte[] salt = new byte[] {1, 2, 3, 4, 5};
        String sectorUriWithProtocol = "https://identity.dev.account.gov.uk";
        String sectorHost = "identity.dev.account.gov.uk";

        Map<String, AttributeValue> userProfileItem =
                Map.of(
                        UserProfile.ATTRIBUTE_SUBJECT_ID,
                        AttributeValue.builder().s(subjectId).build(),
                        UserProfile.ATTRIBUTE_PUBLIC_SUBJECT_ID,
                        AttributeValue.builder().s("public-123").build(),
                        UserProfile.ATTRIBUTE_EMAIL,
                        AttributeValue.builder().s("test@example.com").build(),
                        UserProfile.ATTRIBUTE_UPDATED,
                        AttributeValue.builder().s("2021-07-17T10:30:00.123456").build(),
                        UserProfile.ATTRIBUTE_SALT,
                        AttributeValue.builder().b(SdkBytes.fromByteArray(salt)).build());

        InactiveAccountTrackerItem result =
                buildTrackerItem(userProfileItem, null, sectorUriWithProtocol);

        String expectedPairwiseId =
                ClientSubjectHelper.calculatePairwiseIdentifier(subjectId, sectorHost, salt);

        assertEquals(expectedPairwiseId, result.getCommonSubjectId());
    }
}
