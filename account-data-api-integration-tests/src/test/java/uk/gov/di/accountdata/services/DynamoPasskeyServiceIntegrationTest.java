package uk.gov.di.accountdata.services;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.accountdata.entity.passkey.Passkey;
import uk.gov.di.authentication.accountdata.helpers.CommonTestVariables;
import uk.gov.di.authentication.accountdata.services.DynamoPasskeyService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.extensions.AuthenticatorExtension;

import java.time.LocalDateTime;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeyServiceUpdateFailureReason.PASSKEY_NOT_FOUND;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PRIMARY_PASSKEY_ID;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PUBLIC_SUBJECT_ID;
import static uk.gov.di.authentication.accountdata.helpers.PasskeysTestHelper.buildGenericPasskeyForUserWithSubjectId;
import static uk.gov.di.authentication.accountdata.helpers.PasskeysTestHelper.buildPasskeyForUser;

class DynamoPasskeyServiceIntegrationTest {

    DynamoPasskeyService dynamoPasskeyService =
            new DynamoPasskeyService(ConfigurationService.getInstance());

    @RegisterExtension
    protected static final AuthenticatorExtension authenticatorExtension =
            new AuthenticatorExtension();

    @Nested
    class SavePasskey {

        @Test
        void shouldSavePasskey() {
            // Given
            var passkeyToSave =
                    buildPasskeyForUser(
                            CommonTestVariables.PUBLIC_SUBJECT_ID,
                            CommonTestVariables.CREDENTIAL,
                            PRIMARY_PASSKEY_ID,
                            CommonTestVariables.PASSKEY_AAGUID,
                            true,
                            1,
                            CommonTestVariables.PASSKEY_TRANSPORTS,
                            true,
                            false);

            var expectedSortKey = "PASSKEY#" + PRIMARY_PASSKEY_ID;

            // When
            var passkeySavedResult = dynamoPasskeyService.savePasskeyIfUnique(passkeyToSave);

            // Then
            assertThat(passkeySavedResult, equalTo(true));

            var savedPasskeys =
                    dynamoPasskeyService.getPasskeysForUser(CommonTestVariables.PUBLIC_SUBJECT_ID);

            assertThat(savedPasskeys.size(), equalTo(1));
            Passkey savedPasskey = savedPasskeys.get(0);

            assertThat(savedPasskey.getType(), equalTo("PASSKEY"));
            assertThat(savedPasskey.getSortKey(), equalTo(expectedSortKey));
            assertThat(savedPasskey.getCredential(), equalTo(CommonTestVariables.CREDENTIAL));
            assertThat(
                    savedPasskey.getPublicSubjectId(),
                    equalTo(CommonTestVariables.PUBLIC_SUBJECT_ID));
            assertThat(savedPasskey.getCredentialId(), equalTo(PRIMARY_PASSKEY_ID));
            assertThat(
                    savedPasskey.getPasskeyAaguid(), equalTo(CommonTestVariables.PASSKEY_AAGUID));
            assertThat(savedPasskey.getPasskeyIsAttested(), equalTo(true));
            assertThat(savedPasskey.getPasskeySignCount(), equalTo(1));
            assertThat(
                    savedPasskey.getPasskeyTransports(),
                    equalTo(CommonTestVariables.PASSKEY_TRANSPORTS));
            assertThat(savedPasskey.getPasskeyBackupEligible(), equalTo(true));
            assertThat(savedPasskey.getPasskeyBackedUp(), equalTo(false));
            assertThat(savedPasskey.getLastUsed(), equalTo(null));
        }

        @Test
        void shouldNotSavePasskeyIfAlreadyExists() {
            // Given
            var duplicatePasskey =
                    buildGenericPasskeyForUserWithSubjectId(
                            CommonTestVariables.PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID);
            dynamoPasskeyService.savePasskeyIfUnique(duplicatePasskey);

            // When
            var result = dynamoPasskeyService.savePasskeyIfUnique(duplicatePasskey);

            // Then
            assertThat(result, equalTo(false));
        }
    }

    @Nested
    class GetPasskey {

        @Test
        void shouldGetPasskeysForUser() {
            // Given
            dynamoPasskeyService.savePasskeyIfUnique(
                    buildGenericPasskeyForUserWithSubjectId(
                            CommonTestVariables.PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID));
            dynamoPasskeyService.savePasskeyIfUnique(
                    buildPasskeyForUser(
                            CommonTestVariables.PUBLIC_SUBJECT_ID,
                            CommonTestVariables.CREDENTIAL,
                            CommonTestVariables.SECONDARY_PASSKEY_ID,
                            CommonTestVariables.PASSKEY_AAGUID,
                            false,
                            0,
                            CommonTestVariables.PASSKEY_TRANSPORTS,
                            true,
                            false));
            dynamoPasskeyService.savePasskeyIfUnique(
                    buildGenericPasskeyForUserWithSubjectId(
                            CommonTestVariables.ANOTHER_PUBLIC_SUBJECT_ID,
                            CommonTestVariables.ANOTHER_USER_PASSKEY_ID));

            // When
            var result =
                    dynamoPasskeyService.getPasskeysForUser(CommonTestVariables.PUBLIC_SUBJECT_ID);

            // Then
            assertThat(result.size(), equalTo(2));
            Passkey primaryPasskey = result.get(0);
            Passkey secondaryPasskey = result.get(1);

            assertThat(primaryPasskey.getCredentialId(), equalTo(PRIMARY_PASSKEY_ID));
            assertThat(
                    secondaryPasskey.getCredentialId(),
                    equalTo(CommonTestVariables.SECONDARY_PASSKEY_ID));
            assertThat(primaryPasskey.getPasskeyIsAttested(), equalTo(true));
            assertThat(secondaryPasskey.getPasskeyIsAttested(), equalTo(false));
        }

        @Test
        void shouldGetPasskeyForUserWithPasskeyId() {
            // Given
            dynamoPasskeyService.savePasskeyIfUnique(
                    buildGenericPasskeyForUserWithSubjectId(
                            CommonTestVariables.PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID));
            dynamoPasskeyService.savePasskeyIfUnique(
                    buildGenericPasskeyForUserWithSubjectId(
                            CommonTestVariables.ANOTHER_PUBLIC_SUBJECT_ID,
                            CommonTestVariables.ANOTHER_USER_PASSKEY_ID));

            // When
            var result =
                    dynamoPasskeyService.getPasskeyForUserWithPasskeyId(
                            CommonTestVariables.PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID);

            // Then
            Passkey returnedPasskey = result.orElseThrow();

            assertThat(returnedPasskey.getCredentialId(), equalTo(PRIMARY_PASSKEY_ID));
            assertThat(
                    returnedPasskey.getCredentialId(),
                    not(equalTo(CommonTestVariables.ANOTHER_USER_PASSKEY_ID)));
        }
    }

    @Nested
    class UpdatePasskey {
        @Test
        void shouldUpdatePasskeyForUser() {
            // Given
            var passkeyBeforeUpdate =
                    buildGenericPasskeyForUserWithSubjectId(PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID);
            dynamoPasskeyService.savePasskeyIfUnique(passkeyBeforeUpdate);

            String lastUsedTime = LocalDateTime.now().plusHours(1).toString();
            var updatedSignCount = passkeyBeforeUpdate.getPasskeySignCount() + 1;

            // When
            var updateResult =
                    dynamoPasskeyService.updatePasskey(
                            CommonTestVariables.PUBLIC_SUBJECT_ID,
                            PRIMARY_PASSKEY_ID,
                            lastUsedTime,
                            updatedSignCount);

            // Then
            assertTrue(updateResult.isSuccess());
            var returnedPasskey = updateResult.getSuccess();
            assertEquals(lastUsedTime, returnedPasskey.getLastUsed());
            assertEquals(updatedSignCount, returnedPasskey.getPasskeySignCount());
            assertEquals(PRIMARY_PASSKEY_ID, returnedPasskey.getCredentialId());

            var passkeysInDatabase =
                    dynamoPasskeyService.getPasskeysForUser(CommonTestVariables.PUBLIC_SUBJECT_ID);
            assertEquals(1, passkeysInDatabase.size());
            Passkey updatedPasskey = passkeysInDatabase.get(0);
            assertThat(updatedPasskey.getCredentialId(), equalTo(PRIMARY_PASSKEY_ID));
            assertThat(updatedPasskey.getLastUsed(), equalTo(lastUsedTime));
            assertEquals(updatedSignCount, updatedPasskey.getPasskeySignCount());
        }

        @Test
        void shouldUpdateCorrectPasskeyWhenMultiplePasskeysHaveTheSameId() {
            // Given
            var passkeyBeforeUpdate =
                    buildGenericPasskeyForUserWithSubjectId(PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID);
            dynamoPasskeyService.savePasskeyIfUnique(passkeyBeforeUpdate);
            // Save passkey with same credentialId for another user
            dynamoPasskeyService.savePasskeyIfUnique(
                    buildGenericPasskeyForUserWithSubjectId(
                            CommonTestVariables.ANOTHER_PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID));

            var lastUsedTime = LocalDateTime.now().plusHours(1).toString();
            var updatedSignCount = passkeyBeforeUpdate.getPasskeySignCount() + 1;

            // When
            dynamoPasskeyService.updatePasskey(
                    CommonTestVariables.PUBLIC_SUBJECT_ID,
                    PRIMARY_PASSKEY_ID,
                    lastUsedTime,
                    updatedSignCount);

            // Then
            var initialUsersPasskey =
                    dynamoPasskeyService
                            .getPasskeysForUser(CommonTestVariables.PUBLIC_SUBJECT_ID)
                            .get(0);
            var otherUsersPasskey =
                    dynamoPasskeyService
                            .getPasskeysForUser(CommonTestVariables.ANOTHER_PUBLIC_SUBJECT_ID)
                            .get(0);

            assertThat(initialUsersPasskey.getLastUsed(), equalTo(lastUsedTime));
            assertEquals(updatedSignCount, initialUsersPasskey.getPasskeySignCount());
            assertNull(otherUsersPasskey.getLastUsed());
            assertEquals(1, otherUsersPasskey.getPasskeySignCount());
        }

        @Test
        void shouldReturnFailureIfPasskeyDoesNotExist() {
            // Given
            var passkeyBeforeUpdate =
                    buildGenericPasskeyForUserWithSubjectId(
                            CommonTestVariables.PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID);
            dynamoPasskeyService.savePasskeyIfUnique(passkeyBeforeUpdate);

            String lastUsedTime = LocalDateTime.now().plusHours(1).toString();
            int updatedSignCount = passkeyBeforeUpdate.getPasskeySignCount() + 1;

            // When
            var updateResult =
                    dynamoPasskeyService.updatePasskey(
                            CommonTestVariables.PUBLIC_SUBJECT_ID,
                            "someOtherPasskeyId",
                            lastUsedTime,
                            updatedSignCount);

            // Then
            assertFalse(updateResult.isSuccess());
            var returnedFailure = updateResult.getFailure();
            assertEquals(PASSKEY_NOT_FOUND, returnedFailure);

            var passkeysInDatabase =
                    dynamoPasskeyService.getPasskeysForUser(CommonTestVariables.PUBLIC_SUBJECT_ID);
            assertEquals(1, passkeysInDatabase.size());
            Passkey passkeyInDatabase = passkeysInDatabase.get(0);
            assertNull(passkeyInDatabase.getLastUsed());
            assertEquals(
                    passkeyBeforeUpdate.getPasskeySignCount(),
                    passkeyInDatabase.getPasskeySignCount());
        }
    }

    @Nested
    class DeletePasskey {

        @Test
        void shouldDeleteCorrectPasskeyForUser() {
            // Given
            dynamoPasskeyService.savePasskeyIfUnique(
                    buildGenericPasskeyForUserWithSubjectId(
                            CommonTestVariables.PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID));
            dynamoPasskeyService.savePasskeyIfUnique(
                    buildGenericPasskeyForUserWithSubjectId(
                            CommonTestVariables.PUBLIC_SUBJECT_ID,
                            CommonTestVariables.ANOTHER_PUBLIC_SUBJECT_ID));

            // When
            dynamoPasskeyService.deletePasskey(
                    CommonTestVariables.PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID);

            // Then
            var usersPasskeys =
                    dynamoPasskeyService.getPasskeysForUser(CommonTestVariables.PUBLIC_SUBJECT_ID);
            assertThat(usersPasskeys.size(), equalTo(1));
            assertThat(
                    usersPasskeys.get(0).getCredentialId(),
                    equalTo(CommonTestVariables.ANOTHER_PUBLIC_SUBJECT_ID));
        }
    }
}
