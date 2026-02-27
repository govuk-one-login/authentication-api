package uk.gov.di.authentication.accountdata.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.accountdata.entity.passkey.PasskeysCreateRequest;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.DynamoPasskeyServiceFailureReason;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysCreateServiceFailureReason;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.CREDENTIAL;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PASSKEY_TRANSPORTS;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PRIMARY_PASSKEY_ID;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.PUBLIC_SUBJECT_ID;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.TEST_AAGUID;

class PasskeysCreateServiceTest {

    private final DynamoPasskeyService dynamoPasskeyService = mock(DynamoPasskeyService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    private PasskeysCreateService passkeysCreateService;

    @BeforeEach
    void setUp() {
        passkeysCreateService =
                new PasskeysCreateService(configurationService, dynamoPasskeyService);
    }

    @Nested
    class Success {

        @Test
        void shouldCreatePasskeyGivenValidRequest() {
            // Given
            when(dynamoPasskeyService.savePasskeyIfUnique(any())).thenReturn(Result.success(null));
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
            var result =
                    passkeysCreateService.createPasskey(passkeysCreateRequest, PUBLIC_SUBJECT_ID);

            // Then
            assertThat(result.isSuccess(), equalTo(true));
        }
    }

    @Nested
    class Failure {

        @Test
        void shouldReturnPasskeyExistsIfPasskeyWithCredentialIdExistsForSubjectId() {
            // Given
            when(dynamoPasskeyService.savePasskeyIfUnique(any()))
                    .thenReturn(Result.failure(DynamoPasskeyServiceFailureReason.PASSKEY_EXISTS));
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
            var result =
                    passkeysCreateService.createPasskey(passkeysCreateRequest, PUBLIC_SUBJECT_ID);

            // Then
            assertThat(result.isFailure(), equalTo(true));
            assertThat(
                    result.getFailure(),
                    equalTo(PasskeysCreateServiceFailureReason.PASSKEY_EXISTS));
        }

        @Test
        void shouldReturnFailedToSavePasskeyIfFailedToSavePasskey() {
            // Given
            when(dynamoPasskeyService.savePasskeyIfUnique(any()))
                    .thenReturn(
                            Result.failure(
                                    DynamoPasskeyServiceFailureReason.FAILED_TO_SAVE_PASSKEY));
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
            var result =
                    passkeysCreateService.createPasskey(passkeysCreateRequest, PUBLIC_SUBJECT_ID);

            // Then
            assertThat(result.isFailure(), equalTo(true));
            assertThat(
                    result.getFailure(),
                    equalTo(PasskeysCreateServiceFailureReason.FAILED_TO_SAVE_PASSKEY));
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
