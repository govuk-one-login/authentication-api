package uk.gov.di.authentication.accountdata.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.accountdata.entity.passkey.PasskeysCreateFailureReason;
import uk.gov.di.authentication.accountdata.entity.passkey.PasskeysCreateRequest;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.accountdata.helpers.CommonTestVariables.CREDENTIAL;
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
            var passkeysCreateRequest =
                    buildPasskeysCreateRequest(
                            CREDENTIAL,
                            PRIMARY_PASSKEY_ID,
                            TEST_AAGUID,
                            false,
                            0,
                            List.of("transport1", "transport2"),
                            false,
                            false,
                            false);
            when(dynamoPasskeyService.savePasskeyIfUnique(
                            eq(PUBLIC_SUBJECT_ID),
                            eq(CREDENTIAL),
                            eq(PRIMARY_PASSKEY_ID),
                            eq(TEST_AAGUID),
                            anyBoolean(),
                            anyInt(),
                            anyList(),
                            anyBoolean(),
                            anyBoolean()))
                    .thenReturn(true);

            // When
            var result =
                    passkeysCreateService.createPasskey(passkeysCreateRequest, PUBLIC_SUBJECT_ID);

            // Then
            assertThat(result.isSuccess(), equalTo(true));
        }
    }

    @Nested
    class Validation {
        @Test
        void shouldReturnInvalidAaguidIfInvalidUUID() {
            // Given
            var passkeysCreateRequest =
                    buildPasskeysCreateRequest(
                            "some-credential",
                            "passkey-id",
                            "invalid-aaguid",
                            false,
                            0,
                            List.of("transport1", "transport2"),
                            false,
                            false,
                            false);

            // When
            var result =
                    passkeysCreateService.createPasskey(passkeysCreateRequest, PUBLIC_SUBJECT_ID);

            // Then
            assertThat(result.isFailure(), equalTo(true));
            assertThat(result.getFailure(), equalTo(PasskeysCreateFailureReason.INVALID_AAGUID));
        }

        @Test
        void shouldReturnPasskeyExistsIfPasskeyWithCredentialIdExistsForSubjectId() {
            // Given
            var passkeysCreateRequest =
                    buildPasskeysCreateRequest(
                            "some-credential",
                            "passkey-id",
                            TEST_AAGUID,
                            false,
                            0,
                            List.of("transport1", "transport2"),
                            false,
                            false,
                            false);
            when(dynamoPasskeyService.savePasskeyIfUnique(
                            eq(PUBLIC_SUBJECT_ID),
                            anyString(),
                            anyString(),
                            anyString(),
                            anyBoolean(),
                            anyInt(),
                            anyList(),
                            anyBoolean(),
                            anyBoolean()))
                    .thenReturn(false);

            // When
            var result =
                    passkeysCreateService.createPasskey(passkeysCreateRequest, PUBLIC_SUBJECT_ID);

            // Then
            assertThat(result.isFailure(), equalTo(true));
            assertThat(result.getFailure(), equalTo(PasskeysCreateFailureReason.PASSKEY_EXISTS));
        }
    }

    @Nested
    class Error {

        @Test
        void shouldReturnFailedToSavePasskeyIfExceptionThrown() {
            // Given
            var passkeysCreateRequest =
                    buildPasskeysCreateRequest(
                            "some-credential",
                            "passkey-id",
                            TEST_AAGUID,
                            false,
                            0,
                            List.of("transport1", "transport2"),
                            false,
                            false,
                            false);
            when(dynamoPasskeyService.savePasskeyIfUnique(
                            eq(PUBLIC_SUBJECT_ID),
                            anyString(),
                            anyString(),
                            anyString(),
                            anyBoolean(),
                            anyInt(),
                            anyList(),
                            anyBoolean(),
                            anyBoolean()))
                    .thenThrow(new RuntimeException());

            // When
            var result =
                    passkeysCreateService.createPasskey(passkeysCreateRequest, PUBLIC_SUBJECT_ID);

            // Then
            assertThat(result.isFailure(), equalTo(true));
            assertThat(
                    result.getFailure(),
                    equalTo(PasskeysCreateFailureReason.FAILED_TO_SAVE_PASSKEY));
        }
    }

    private PasskeysCreateRequest buildPasskeysCreateRequest(
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
