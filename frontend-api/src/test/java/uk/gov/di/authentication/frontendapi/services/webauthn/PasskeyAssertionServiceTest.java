package uk.gov.di.authentication.frontendapi.services.webauthn;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.exception.AssertionFailedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.FinishPasskeyAssertionFailureReason;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class PasskeyAssertionServiceTest {
    private final RelyingParty relyingParty = mock(RelyingParty.class);
    private final PasskeyJsonParser jsonParser = mock(PasskeyJsonParser.class);
    private PasskeyAssertionService passkeyAssertionService;

    @BeforeEach
    void setup() {
        passkeyAssertionService = new PasskeyAssertionService(relyingParty, jsonParser);
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

                // When
                AssertionRequest actualAssertionRequest =
                        passkeyAssertionService.startAssertion("");

                // Then
                assertEquals(mockAssertionRequest, actualAssertionRequest);
            }
        }
    }

    @Nested
    class FinishAssertion {
        @Nested
        class Success {
            @Test
            @SuppressWarnings("unchecked")
            void shouldReturnAssertionResultIfAssertionSucceeded()
                    throws IOException, AssertionFailedException {
                // Given
                when(jsonParser.parseAssertionRequest(any()))
                        .thenReturn(mock(AssertionRequest.class));
                when(jsonParser.parsePublicKeyCredential(any()))
                        .thenReturn(mock(PublicKeyCredential.class));
                AssertionResult mockAssertionResult = mock(AssertionResult.class);
                when(mockAssertionResult.isSuccess()).thenReturn(true);
                when(relyingParty.finishAssertion(any())).thenReturn(mockAssertionResult);

                // When
                AssertionResult actualAssertionResult =
                        passkeyAssertionService.finishAssertion("", "").getSuccess();

                // Then
                assertEquals(actualAssertionResult, mockAssertionResult);
            }
        }

        @Nested
        class Error {
            @Test
            void shouldFailWithParsingAssertionRequestErrorWhenAssertionRequestJsonParsingFails()
                    throws JsonProcessingException {
                // Given
                when(jsonParser.parseAssertionRequest(any()))
                        .thenThrow(JsonProcessingException.class);

                // When
                FinishPasskeyAssertionFailureReason actualFailureReason =
                        passkeyAssertionService.finishAssertion("", "").getFailure();

                // Then
                assertEquals(
                        FinishPasskeyAssertionFailureReason.PARSING_ASSERTION_REQUEST_ERROR,
                        actualFailureReason);
            }

            @Test
            void shouldFailWithParsingPkcErrorWhenPKCJsonParsingFails() throws IOException {
                // Given
                when(jsonParser.parseAssertionRequest(any()))
                        .thenReturn(mock(AssertionRequest.class));
                when(jsonParser.parsePublicKeyCredential(any())).thenThrow(IOException.class);

                // When
                FinishPasskeyAssertionFailureReason actualFailureReason =
                        passkeyAssertionService.finishAssertion("", "").getFailure();

                // Then
                assertEquals(
                        FinishPasskeyAssertionFailureReason.PARSING_PKC_ERROR, actualFailureReason);
            }

            @Test
            @SuppressWarnings("unchecked")
            void shouldFailWithAssertionFailedErrorWhenAssertionFails()
                    throws IOException, AssertionFailedException {
                // Given
                when(jsonParser.parseAssertionRequest(any()))
                        .thenReturn(mock(AssertionRequest.class));
                when(jsonParser.parsePublicKeyCredential(any()))
                        .thenReturn(mock(PublicKeyCredential.class));
                when(relyingParty.finishAssertion(any())).thenThrow(AssertionFailedException.class);

                // When
                FinishPasskeyAssertionFailureReason actualFailureReason =
                        passkeyAssertionService.finishAssertion("", "").getFailure();

                // Then
                assertEquals(
                        FinishPasskeyAssertionFailureReason.ASSERTION_FAILED_ERROR,
                        actualFailureReason);
            }

            @Test
            @SuppressWarnings("unchecked")
            void shouldFailWithAssertionFailedErrorWhenAssertionIsNotSuccessful()
                    throws IOException, AssertionFailedException {
                // Given
                when(jsonParser.parseAssertionRequest(any()))
                        .thenReturn(mock(AssertionRequest.class));
                when(jsonParser.parsePublicKeyCredential(any()))
                        .thenReturn(mock(PublicKeyCredential.class));
                AssertionResult mockAssertionResult = mock(AssertionResult.class);
                when(mockAssertionResult.isSuccess()).thenReturn(false);
                when(relyingParty.finishAssertion(any())).thenReturn(mockAssertionResult);

                // When
                FinishPasskeyAssertionFailureReason actualFailureReason =
                        passkeyAssertionService.finishAssertion("", "").getFailure();

                // Then
                assertEquals(
                        FinishPasskeyAssertionFailureReason.ASSERTION_FAILED_ERROR,
                        actualFailureReason);
            }
        }
    }
}
