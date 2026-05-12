package uk.gov.di.authentication.accountdata.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.accountdata.entity.passkey.Passkey;
import uk.gov.di.authentication.accountdata.entity.passkey.PasskeysCreateRequest;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysCreateFailureReason;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysDeleteFailureReason;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysRetrieveFailureReasons;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysUpdateFailureReason;
import uk.gov.di.authentication.accountdata.helpers.CommonTestVariables;
import uk.gov.di.authentication.accountdata.helpers.PasskeysTestHelper;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Stream;

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
    class CreatePasskey {

        @Nested
        class Success {

            @Test
            void shouldCreatePasskeyGivenValidRequest() {
                // Given
                when(persistentService.savePasskeyIfUnique(any())).thenReturn(Result.success(null));
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
                        passkeysService.createPasskey(passkeysCreateRequest, PUBLIC_SUBJECT_ID);

                // Then
                assertThat(result.isSuccess(), equalTo(true));
            }
        }

        @Nested
        class Failure {

            @Test
            void shouldReturnPasskeyExistsIfPasskeyWithCredentialIdExistsForSubjectId() {
                // Given
                when(persistentService.savePasskeyIfUnique(any()))
                        .thenReturn(Result.failure(PasskeysCreateFailureReason.PASSKEY_EXISTS));
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
                        passkeysService.createPasskey(passkeysCreateRequest, PUBLIC_SUBJECT_ID);

                // Then
                assertThat(result.isFailure(), equalTo(true));
                assertThat(
                        result.getFailure(), equalTo(PasskeysCreateFailureReason.PASSKEY_EXISTS));
            }

            @Test
            void shouldReturnFailedToSavePasskeyIfFailedToSavePasskey() {
                // Given
                when(persistentService.savePasskeyIfUnique(any()))
                        .thenReturn(
                                Result.failure(PasskeysCreateFailureReason.FAILED_TO_SAVE_PASSKEY));
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
                        passkeysService.createPasskey(passkeysCreateRequest, PUBLIC_SUBJECT_ID);

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

    @Nested
    class RetrievePasskeys {

        @Nested
        class Success {

            @Test
            void shouldRetrievePasskeys() {
                // Given
                var returnedPasskeys =
                        List.of(
                                PasskeysTestHelper.buildGenericPasskeyForUserWithSubjectId(
                                        CommonTestVariables.PUBLIC_SUBJECT_ID,
                                        CommonTestVariables.PRIMARY_PASSKEY_ID),
                                PasskeysTestHelper.buildGenericPasskeyForUserWithSubjectId(
                                        CommonTestVariables.PUBLIC_SUBJECT_ID,
                                        CommonTestVariables.SECONDARY_PASSKEY_ID));
                when(persistentService.getPasskeysForUser(CommonTestVariables.PUBLIC_SUBJECT_ID))
                        .thenReturn(returnedPasskeys);

                // When
                var result =
                        passkeysService.retrievePasskeys(CommonTestVariables.PUBLIC_SUBJECT_ID);

                // Then
                assertTrue(result.isSuccess());
                assertThat(result.getSuccess(), equalTo(returnedPasskeys));
            }
        }

        @Nested
        class Failure {

            @Test
            void shouldReturnFailedToGetPasskeysIfExceptionThrown() {
                // Given
                when(persistentService.getPasskeysForUser(CommonTestVariables.PUBLIC_SUBJECT_ID))
                        .thenThrow(RuntimeException.class);

                // When
                var result =
                        passkeysService.retrievePasskeys(CommonTestVariables.PUBLIC_SUBJECT_ID);

                // Then
                assertTrue(result.isFailure());
                assertThat(
                        result.getFailure(),
                        equalTo(PasskeysRetrieveFailureReasons.FAILED_TO_GET_PASSKEYS));
            }
        }
    }

    @Nested
    class DeletePasskey {

        @Nested
        class Success {
            private static Stream<Result<PasskeysDeleteFailureReason, Void>> deleteResults() {
                return Stream.of(
                        Result.success(null),
                        Result.failure(PasskeysDeleteFailureReason.PASSKEY_NOT_FOUND));
            }

            @MethodSource("deleteResults")
            @ParameterizedTest
            void shouldReturnResultFromDynamoServiceWhenNoErrorOccurs(
                    Result<PasskeysDeleteFailureReason, Void> passkeyDeleteResult) {
                // Given
                when(persistentService.deletePasskey(PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID))
                        .thenReturn(passkeyDeleteResult);

                // When
                var result =
                        passkeysService.deletePasskey(
                                CommonTestVariables.PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID);

                // Then
                assertEquals(passkeyDeleteResult, result);
            }
        }

        @Nested
        class Failure {
            @Test
            void shouldReturnFailedToDeletePasskeysIfExceptionThrown() {
                // Given
                when(persistentService.deletePasskey(
                                CommonTestVariables.PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID))
                        .thenThrow(RuntimeException.class);

                // When
                var result =
                        passkeysService.deletePasskey(
                                CommonTestVariables.PUBLIC_SUBJECT_ID, PRIMARY_PASSKEY_ID);

                // Then
                assertTrue(result.isFailure());
                assertThat(
                        result.getFailure(),
                        equalTo(PasskeysDeleteFailureReason.FAILED_TO_DELETE_PASSKEY));
            }
        }
    }
}
