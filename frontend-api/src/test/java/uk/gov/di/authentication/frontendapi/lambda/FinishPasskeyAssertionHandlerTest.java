package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.yubico.webauthn.AssertionResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.FinishPasskeyAssertionFailureReason;
import uk.gov.di.authentication.frontendapi.services.webauthn.PasskeyAssertionService;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class FinishPasskeyAssertionHandlerTest {
    private final Context context = mock(Context.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final PasskeyAssertionService passkeyAssertionService =
            mock(PasskeyAssertionService.class);
    private FinishPasskeyAssertionHandler handler;
    private final AuthSessionItem authSession = new AuthSessionItem().withSessionId(SESSION_ID);

    @BeforeEach
    void setup() {
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
        when(authSessionService.getSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(authSession));

        handler =
                new FinishPasskeyAssertionHandler(
                        configurationService,
                        authenticationService,
                        authSessionService,
                        passkeyAssertionService);
    }

    @Nested
    class Success {
        @Test
        void shouldReturn200WhenPasskeyAssertionSuccessful() {
            // Given
            AssertionResult mockAssertionResult = mock(AssertionResult.class);
            when(mockAssertionResult.isSuccess()).thenReturn(true);
            when(passkeyAssertionService.finishAssertion(any(), any()))
                    .thenReturn(Result.success(mockAssertionResult));

            // When
            var response = handler.handleRequest(finishPasskeyAssertionRequest(), context);

            // Then
            assertThat(response, hasStatus(200));
        }
    }

    @Nested
    class Validation {
        @Test
        void shouldReturn400WhenRequestBodyMissingPKC() {
            // Given
            var request = finishPasskeyAssertionRequest("{}");

            // When
            var response = handler.handleRequest(request, context);

            // Then
            assertThat(response, hasStatus(400));
            assertThat(response, hasJsonBody(ErrorResponse.REQUEST_MISSING_PARAMS));
        }
    }

    @Nested
    class Error {
        @Test
        void shouldReturn500WhenAssertionRequestDeserializationFails() {
            // Given
            when(passkeyAssertionService.finishAssertion(any(), any()))
                    .thenReturn(
                            Result.failure(
                                    FinishPasskeyAssertionFailureReason
                                            .PARSING_ASSERTION_REQUEST_ERROR));

            // When
            var response = handler.handleRequest(finishPasskeyAssertionRequest(), context);

            // Then
            assertThat(response, hasStatus(500));
            assertThat(response, hasJsonBody(ErrorResponse.UNEXPECTED_INTERNAL_API_ERROR));
        }

        @Test
        void shouldReturn400WhenPKCDeserializationFails() {
            // Given
            when(passkeyAssertionService.finishAssertion(any(), any()))
                    .thenReturn(
                            Result.failure(FinishPasskeyAssertionFailureReason.PARSING_PKC_ERROR));

            // When
            var response = handler.handleRequest(finishPasskeyAssertionRequest(), context);

            // Then
            assertThat(response, hasStatus(400));
            assertThat(response, hasJsonBody(ErrorResponse.PASSKEY_ASSERTION_INVALID_PKC));
        }

        @Test
        void shouldReturn401WhenPasskeyAssertionFailed() {
            // Given
            when(passkeyAssertionService.finishAssertion(any(), any()))
                    .thenReturn(
                            Result.failure(
                                    FinishPasskeyAssertionFailureReason.ASSERTION_FAILED_ERROR));

            // When
            var response = handler.handleRequest(finishPasskeyAssertionRequest(), context);

            // Then
            assertThat(response, hasStatus(401));
            assertThat(response, hasJsonBody(ErrorResponse.PASSKEY_ASSERTION_FAILED));
        }

        @Test
        void shouldReturn401WhenPasskeyAssertionUnsuccessful() {
            // Given
            AssertionResult mockAssertionResult = mock(AssertionResult.class);
            when(mockAssertionResult.isSuccess()).thenReturn(false);
            when(passkeyAssertionService.finishAssertion(any(), any()))
                    .thenReturn(Result.success(mockAssertionResult));

            // When
            var response = handler.handleRequest(finishPasskeyAssertionRequest(), context);

            // Then
            assertThat(response, hasStatus(401));
            assertThat(response, hasJsonBody(ErrorResponse.PASSKEY_ASSERTION_FAILED));
        }
    }

    private APIGatewayProxyRequestEvent finishPasskeyAssertionRequest(String body) {
        return new APIGatewayProxyRequestEvent()
                .withHeaders(VALID_HEADERS)
                .withBody(body)
                .withRequestContext(contextWithSourceIp(IP_ADDRESS));
    }

    private APIGatewayProxyRequestEvent finishPasskeyAssertionRequest() {
        return finishPasskeyAssertionRequest("""
            {"pkc": ""}
            """);
    }
}
