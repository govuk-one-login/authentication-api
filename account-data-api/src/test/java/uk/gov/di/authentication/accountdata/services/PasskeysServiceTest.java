package uk.gov.di.authentication.accountdata.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.accountdata.entity.passkey.Passkey;
import uk.gov.di.authentication.accountdata.entity.passkey.PasskeysCreateRequest;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysCreateServiceFailureReason;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysUpdateFailureReason;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.time.LocalDateTime;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.CREDENTIAL;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PASSKEY_TRANSPORTS;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PRIMARY_PASSKEY_ID;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PUBLIC_SUBJECT_ID;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.TEST_AAGUID;

class PasskeysServiceTest {

    private final DynamoPasskeyService persistentService = mock(DynamoPasskeyService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    private PasskeysService passkeysService;

    @BeforeEach
    void setUp() {
        passkeysService = new PasskeysService(configurationService, persistentService);
    }

    @Nested
    class Success {

        @Test
        void shouldCreatePasskeyGivenValidRequest() {
            // Given
            when(persistentService.savePasskeyIfUnique(any())).thenReturn(true);
            var passkeysCreateRequest =
                    buildPasskeysCreateRequest(
                            CREDENTIAL,
                            PRIMARY_PASSKEY_ID,
                            TEST_AAGUID,
                            false,
                            0,
                            PASSKEY_TRANSPORTS,
                            false,
                            false,
                            false);

            // When
            var result = passkeysService.createPasskey(passkeysCreateRequest, PUBLIC_SUBJECT_ID);

            // Then
            assertThat(result.isSuccess(), equalTo(true));
        }
    }

    @Nested
    class Failure {

        @Test
        void shouldReturnPasskeyExistsIfPasskeyWithCredentialIdExistsForSubjectId() {
            // Given
            when(persistentService.savePasskeyIfUnique(any())).thenReturn(false);
            var passkeysCreateRequest =
                    buildPasskeysCreateRequest(
                            CREDENTIAL,
                            PRIMARY_PASSKEY_ID,
                            TEST_AAGUID,
                            false,
                            0,
                            PASSKEY_TRANSPORTS,
                            false,
                            false,
                            false);

            // When
            var result = passkeysService.createPasskey(passkeysCreateRequest, PUBLIC_SUBJECT_ID);

            // Then
            assertThat(result.isFailure(), equalTo(true));
            assertThat(
                    result.getFailure(),
                    equalTo(PasskeysCreateServiceFailureReason.PASSKEY_EXISTS));
        }

        @Test
        void shouldReturnFailedToSavePasskeyIfExceptionThrown() {
            // Given
            when(persistentService.savePasskeyIfUnique(any())).thenThrow(new RuntimeException());
            var passkeysCreateRequest =
                    buildPasskeysCreateRequest(
                            CREDENTIAL,
                            PRIMARY_PASSKEY_ID,
                            TEST_AAGUID,
                            false,
                            0,
                            PASSKEY_TRANSPORTS,
                            false,
                            false,
                            false);

            // When
            var result = passkeysService.createPasskey(passkeysCreateRequest, PUBLIC_SUBJECT_ID);

            // Then
            assertThat(result.isFailure(), equalTo(true));
            assertThat(
                    result.getFailure(),
                    equalTo(PasskeysCreateServiceFailureReason.FAILED_TO_SAVE_PASSKEY));
        }
    }

    @Nested
    class UpdatePasskey {

        private final String lastUsed = LocalDateTime.now().toString();
        private final int signCount = 1;

        @Test
        void shouldUpdatePasskeySuccessfully() {
            // Given
            var passkey = new Passkey();
            when(persistentService.updatePasskey(
                            PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID, lastUsed, signCount))
                    .thenReturn(Result.success(passkey));

            // When
            var result =
                    passkeysService.updatePasskey(
                            PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID, lastUsed, signCount);

            // Then
            verify(persistentService)
                    .updatePasskey(PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID, lastUsed, signCount);
            assertTrue(result.isSuccess());
            assertEquals(result.getSuccess(), passkey);
        }

        @Test
        void shouldReturnFailureWhenDynamoPasskeyServiceReturnsFailure() {
            // Given
            when(persistentService.updatePasskey(
                            PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID, lastUsed, signCount))
                    .thenReturn(Result.failure(PasskeysUpdateFailureReason.PASSKEY_NOT_FOUND));

            // When
            var result =
                    passkeysService.updatePasskey(
                            PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID, lastUsed, signCount);

            // Then
            assertThat(result.isFailure(), equalTo(true));
            assertThat(result.getFailure(), equalTo(PasskeysUpdateFailureReason.PASSKEY_NOT_FOUND));
        }

        @Test
        void shouldReturnFailureWhenExceptionIsThrownDuringUpdate() {
            // Given
            when(persistentService.updatePasskey(
                            PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID, lastUsed, signCount))
                    .thenThrow(new RuntimeException("database connection failure"));

            // When
            var result =
                    passkeysService.updatePasskey(
                            PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID, lastUsed, signCount);

            // Then
            assertThat(result.isFailure(), equalTo(true));
            assertThat(
                    result.getFailure(),
                    equalTo(PasskeysUpdateFailureReason.FAILED_TO_UPDATE_PASSKEY));
        }
    }

    public PasskeysCreateRequest buildPasskeysCreateRequest(
            String credential,
            String passkeyId,
            String aaguid,
            boolean isAttested,
            int signCount,
            List<String> transports,
            boolean isBackUpEligible,
            boolean isBackedUp,
            boolean isResidentKey) {
        return new PasskeysCreateRequest(
                credential,
                passkeyId,
                aaguid,
                isAttested,
                signCount,
                transports,
                isBackUpEligible,
                isBackedUp,
                isResidentKey);
    }
}
