package uk.gov.di.accountdata.services;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.accountdata.helpers.CommonTestVariables;
import uk.gov.di.authentication.accountdata.entity.passkey.Passkey;
import uk.gov.di.authentication.accountdata.services.DynamoPasskeyService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.extensions.AuthenticatorExtension;

import java.time.LocalDateTime;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;

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
            savePasskeyForUser(
                    CommonTestVariables.PUBLIC_SUBJECT_ID,
                    CommonTestVariables.PRIMARY_PASSKEY_ID,
                    CommonTestVariables.PASSKEY_AAGUID,
                    true,
                    1,
                    CommonTestVariables.PASSKEY_TRANSPORTS,
                    true,
                    false);

            var result =
                    dynamoPasskeyService.getPasskeysForUser(CommonTestVariables.PUBLIC_SUBJECT_ID);

            assertThat(result.size(), equalTo(1));
            Passkey savedPasskey = result.get(0);

            assertThat(savedPasskey.getCredential(), equalTo("PASSKEY"));
            assertThat(
                    savedPasskey.getPublicSubjectId(),
                    equalTo(CommonTestVariables.PUBLIC_SUBJECT_ID));
            assertThat(
                    savedPasskey.getCredentialId(),
                    equalTo(CommonTestVariables.PRIMARY_PASSKEY_ID));
            assertThat(
                    savedPasskey.getPasskeyAaguid(), equalTo(CommonTestVariables.PASSKEY_AAGUID));
            assertThat(savedPasskey.getPasskeyIsAttested(), equalTo(true));
            assertThat(savedPasskey.getPasskeySignCount(), equalTo(1));
            assertThat(
                    savedPasskey.getPasskeyTransports(),
                    equalTo(CommonTestVariables.PASSKEY_TRANSPORTS));
            assertThat(savedPasskey.getPasskeyBackupEligible(), equalTo(true));
            assertThat(savedPasskey.getPasskeyBackedUp(), equalTo(false));
        }
    }

    @Nested
    class GetPasskey {

        @Test
        void shouldGetPasskeysForUser() {
            saveGenericPasskeyForUser(
                    CommonTestVariables.PUBLIC_SUBJECT_ID, CommonTestVariables.PRIMARY_PASSKEY_ID);
            savePasskeyForUser(
                    CommonTestVariables.PUBLIC_SUBJECT_ID,
                    CommonTestVariables.SECONDARY_PASSKEY_ID,
                    CommonTestVariables.PASSKEY_AAGUID,
                    false,
                    0,
                    CommonTestVariables.PASSKEY_TRANSPORTS,
                    true,
                    false);
            saveGenericPasskeyForUser(
                    CommonTestVariables.ANOTHER_PUBLIC_SUBJECT_ID,
                    CommonTestVariables.ANOTHER_USER_PASSKEY_ID);

            var result =
                    dynamoPasskeyService.getPasskeysForUser(CommonTestVariables.PUBLIC_SUBJECT_ID);

            assertThat(result.size(), equalTo(2));
            Passkey primaryPasskey = result.get(0);
            Passkey secondaryPasskey = result.get(1);

            assertThat(
                    primaryPasskey.getCredentialId(),
                    equalTo(CommonTestVariables.PRIMARY_PASSKEY_ID));
            assertThat(
                    secondaryPasskey.getCredentialId(),
                    equalTo(CommonTestVariables.SECONDARY_PASSKEY_ID));
            assertThat(primaryPasskey.getPasskeyIsAttested(), equalTo(true));
            assertThat(secondaryPasskey.getPasskeyIsAttested(), equalTo(false));
        }

        @Test
        void shouldGetPasskeyForUserWithPasskeyId() {
            saveGenericPasskeyForUser(
                    CommonTestVariables.PUBLIC_SUBJECT_ID, CommonTestVariables.PRIMARY_PASSKEY_ID);
            saveGenericPasskeyForUser(
                    CommonTestVariables.ANOTHER_PUBLIC_SUBJECT_ID,
                    CommonTestVariables.ANOTHER_USER_PASSKEY_ID);

            var result =
                    dynamoPasskeyService.getPasskeyForUserWithPasskeyId(
                            CommonTestVariables.PUBLIC_SUBJECT_ID,
                            CommonTestVariables.PRIMARY_PASSKEY_ID);

            Passkey returnedPasskey = result.orElseThrow();

            assertThat(
                    returnedPasskey.getCredentialId(),
                    equalTo(CommonTestVariables.PRIMARY_PASSKEY_ID));
            assertThat(
                    returnedPasskey.getCredentialId(),
                    not(equalTo(CommonTestVariables.ANOTHER_USER_PASSKEY_ID)));
        }
    }

    @Nested
    class UpdatePasskey {
        @Test
        void shouldUpdatePasskeyForUser() {
            saveGenericPasskeyForUser(
                    CommonTestVariables.PUBLIC_SUBJECT_ID, CommonTestVariables.PRIMARY_PASSKEY_ID);

            String lastUsedTime = LocalDateTime.now().plusHours(1).toString();
            dynamoPasskeyService.updatePasskey(
                    CommonTestVariables.PUBLIC_SUBJECT_ID,
                    CommonTestVariables.PRIMARY_PASSKEY_ID,
                    lastUsedTime);

            var result =
                    dynamoPasskeyService.getPasskeysForUser(CommonTestVariables.PUBLIC_SUBJECT_ID);
            Passkey updatedPasskey = result.get(0);
            assertThat(
                    updatedPasskey.getCredentialId(),
                    equalTo(CommonTestVariables.PRIMARY_PASSKEY_ID));
            assertThat(updatedPasskey.getLastUsed(), equalTo(lastUsedTime));
        }

        @Test
        void shouldUpdateCorrectPasskeyWhenMultiplePasskeysHaveTheSameId() {
            saveGenericPasskeyForUser(
                    CommonTestVariables.PUBLIC_SUBJECT_ID, CommonTestVariables.PRIMARY_PASSKEY_ID);
            // Save passkey with same credentialId for another user
            saveGenericPasskeyForUser(
                    CommonTestVariables.ANOTHER_PUBLIC_SUBJECT_ID,
                    CommonTestVariables.PRIMARY_PASSKEY_ID);

            String lastUsedTime = LocalDateTime.now().plusHours(1).toString();
            dynamoPasskeyService.updatePasskey(
                    CommonTestVariables.PUBLIC_SUBJECT_ID,
                    CommonTestVariables.PRIMARY_PASSKEY_ID,
                    lastUsedTime);

            Passkey initialUsersPasskey =
                    dynamoPasskeyService
                            .getPasskeysForUser(CommonTestVariables.PUBLIC_SUBJECT_ID)
                            .get(0);
            Passkey otherUsersPasskey =
                    dynamoPasskeyService
                            .getPasskeysForUser(CommonTestVariables.ANOTHER_PUBLIC_SUBJECT_ID)
                            .get(0);

            assertThat(initialUsersPasskey.getLastUsed(), equalTo(lastUsedTime));
            assertThat(otherUsersPasskey.getLastUsed(), equalTo(null));
        }
    }

    private void saveGenericPasskeyForUser(String publicSubjectId, String passkeyId) {
        savePasskeyForUser(
                publicSubjectId,
                passkeyId,
                CommonTestVariables.PASSKEY_AAGUID,
                true,
                1,
                CommonTestVariables.PASSKEY_TRANSPORTS,
                true,
                false);
    }

    private void savePasskeyForUser(
            String publicSubjectId,
            String passkeyId,
            String aaguid,
            boolean isAttested,
            int signCount,
            List<String> transports,
            boolean backupEligible,
            boolean backedUp) {
        dynamoPasskeyService.savePasskey(
                publicSubjectId,
                passkeyId,
                aaguid,
                isAttested,
                signCount,
                transports,
                backupEligible,
                backedUp);
    }
}
