package uk.gov.di.authentication.frontendapi.services.webauthn;

import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.AssertionFailedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.FinishPasskeyAssertionFailureReason;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.PUBLIC_SUBJECT_ID;

class PasskeyAssertionServiceTest {
    private final RelyingParty relyingParty = mock(RelyingParty.class);
    private PasskeyAssertionService passkeyAssertionService;
    private static final PublicKeyCredential<
                    AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
            credential = mock(PublicKeyCredential.class);

    @BeforeEach
    void setup() {
        passkeyAssertionService = new PasskeyAssertionService(relyingParty);
    }

    @Nested
    class StartAssertion {
        @Nested
        class Success {
            @Test
            void shouldReturnAssertionRequestIfRelyingPartyStartAssertionSucceeds() {
                // Given
                var mockAssertionRequest = mock(AssertionRequest.class);
                when(relyingParty.startAssertion(any())).thenReturn(mockAssertionRequest);

                var expectedStartAssertionOptions =
                        StartAssertionOptions.builder()
                                .userHandle(
                                        Optional.of(
                                                new ByteArray(
                                                        PUBLIC_SUBJECT_ID.getBytes(
                                                                StandardCharsets.UTF_8))))
                                .userVerification(UserVerificationRequirement.REQUIRED)
                                .build();

                // When
                AssertionRequest actualAssertionRequest =
                        passkeyAssertionService.startAssertion(PUBLIC_SUBJECT_ID);

                // Then
                assertEquals(mockAssertionRequest, actualAssertionRequest);
                verify(relyingParty).startAssertion(expectedStartAssertionOptions);
            }
        }
    }

    @Nested
    class FinishAssertion {
        @Nested
        class Success {
            @Test
            @SuppressWarnings("unchecked")
            void shouldReturnAssertionResultIfAssertionSucceeded() throws AssertionFailedException {
                // Given
                AssertionResult mockAssertionResult = mock(AssertionResult.class);
                when(mockAssertionResult.isSuccess()).thenReturn(true);
                when(relyingParty.finishAssertion(any())).thenReturn(mockAssertionResult);

                // When
                AssertionResult actualAssertionResult =
                        passkeyAssertionService
                                .finishAssertion(mock(AssertionRequest.class), credential)
                                .getSuccess();

                // Then
                assertEquals(actualAssertionResult, mockAssertionResult);
            }
        }

        @Nested
        class Error {
            @Test
            @SuppressWarnings("unchecked")
            void shouldFailWithAssertionFailedErrorWhenAssertionFails()
                    throws AssertionFailedException {
                // Given
                when(relyingParty.finishAssertion(any())).thenThrow(AssertionFailedException.class);

                // When
                FinishPasskeyAssertionFailureReason actualFailureReason =
                        passkeyAssertionService
                                .finishAssertion(mock(AssertionRequest.class), credential)
                                .getFailure();

                // Then
                assertEquals(
                        FinishPasskeyAssertionFailureReason.ASSERTION_FAILED_ERROR,
                        actualFailureReason);
            }

            @Test
            @SuppressWarnings("unchecked")
            void shouldFailWithAssertionFailedErrorWhenAssertionIsNotSuccessful()
                    throws AssertionFailedException {
                // Given
                AssertionResult mockAssertionResult = mock(AssertionResult.class);
                when(mockAssertionResult.isSuccess()).thenReturn(false);
                when(relyingParty.finishAssertion(any())).thenReturn(mockAssertionResult);

                // When
                FinishPasskeyAssertionFailureReason actualFailureReason =
                        passkeyAssertionService
                                .finishAssertion(mock(AssertionRequest.class), credential)
                                .getFailure();

                // Then
                assertEquals(
                        FinishPasskeyAssertionFailureReason.ASSERTION_FAILED_ERROR,
                        actualFailureReason);
            }
        }
    }
}
