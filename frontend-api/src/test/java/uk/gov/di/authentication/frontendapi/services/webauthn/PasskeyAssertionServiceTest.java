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

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
    class Success {
        @Test
        @SuppressWarnings("unchecked")
        void shouldReturnAssertionResultIfAssertionSucceeded()
                throws IOException, AssertionFailedException {
            // Given
            when(jsonParser.parseAssertionRequest(any())).thenReturn(mock(AssertionRequest.class));
            when(jsonParser.parsePublicKeyCredential(any()))
                    .thenReturn(mock(PublicKeyCredential.class));
            AssertionResult mockAssertionResult = mock(AssertionResult.class);
            when(relyingParty.finishAssertion(any())).thenReturn(mockAssertionResult);

            // When
            AssertionResult actualAssertionResult = passkeyAssertionService.finishAssertion("", "");

            // Then
            assertEquals(actualAssertionResult, mockAssertionResult);
        }
    }

    @Nested
    class Error {
        @Test
        void shouldThrowIOExceptionWhenAssertionRequestJsonParsingFails()
                throws JsonProcessingException {
            // Given
            when(jsonParser.parseAssertionRequest(any())).thenThrow(JsonProcessingException.class);

            // When/Then
            assertThrows(
                    IOException.class,
                    () -> {
                        passkeyAssertionService.finishAssertion("", "");
                    });
        }

        @Test
        void shouldThrowIOExceptionWhenPKCJsonParsingFails() throws IOException {
            // Given
            when(jsonParser.parseAssertionRequest(any())).thenReturn(mock(AssertionRequest.class));
            when(jsonParser.parsePublicKeyCredential(any())).thenThrow(IOException.class);

            // When/Then
            assertThrows(
                    IOException.class,
                    () -> {
                        passkeyAssertionService.finishAssertion("", "");
                    });
        }

        @Test
        @SuppressWarnings("unchecked")
        void shouldThrowAssertionFailedExceptionWhenAssertionFails()
                throws IOException, AssertionFailedException {
            // Given
            when(jsonParser.parseAssertionRequest(any())).thenReturn(mock(AssertionRequest.class));
            when(jsonParser.parsePublicKeyCredential(any()))
                    .thenReturn(mock(PublicKeyCredential.class));
            when(relyingParty.finishAssertion(any())).thenThrow(AssertionFailedException.class);

            // When/Then
            assertThrows(
                    AssertionFailedException.class,
                    () -> {
                        passkeyAssertionService.finishAssertion("", "");
                    });
        }
    }
}
