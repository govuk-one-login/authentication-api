package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.yubico.webauthn.AssertionResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import uk.gov.di.authentication.frontendapi.entity.FinishPasskeyAssertionFailureReason;
import uk.gov.di.authentication.frontendapi.services.webauthn.PasskeyAssertionService;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.userpermissions.UserActionsManager;

import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.PASSKEY_AUTHENTICATION_SUCCESSFUL;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.PASSKEY_VERIFICATION_FAILED;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.PASSKEY_VERIFICATION_SUCCESSFUL;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.VALID_HEADERS;
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
    private final UserActionsManager userActionsManager = mock(UserActionsManager.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private FinishPasskeyAssertionHandler handler;
    private final AuthSessionItem authSession = new AuthSessionItem().withSessionId(SESSION_ID);

    private static final String ENV = "test";

    @BeforeEach
    void setup() {
        when(configurationService.getEnvironment()).thenReturn("test");
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
        when(authSessionService.getSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(authSession));

        handler =
                new FinishPasskeyAssertionHandler(
                        configurationService,
                        authenticationService,
                        authSessionService,
                        passkeyAssertionService,
                        userActionsManager,
                        cloudwatchMetricsService);
    }

    @Nested
    class Success {
        @Test
        void shouldReturn200WhenPasskeyAssertionSuccessful() {
            // Given
            AssertionResult mockAssertionResult = mock(AssertionResult.class);
            when(passkeyAssertionService.finishAssertion(any(), any(), any(), any()))
                    .thenReturn(Result.success(mockAssertionResult));

            // When
            var response = handler.handleRequest(finishPasskeyAssertionRequest(), context);

            // Then
            assertThat(response, hasStatus(200));
        }

        @Test
        void shouldReportCorrectPasskeyReceivedWhenAssertionSuccessful() {
            // Given
            AssertionResult mockAssertionResult = mock(AssertionResult.class);
            when(passkeyAssertionService.finishAssertion(any(), any(), any(), any()))
                    .thenReturn(Result.success(mockAssertionResult));

            // When
            handler.handleRequest(finishPasskeyAssertionRequest(), context);

            // Then
            verify(userActionsManager, times(1)).correctPasskeyReceived(any(), any());
            verify(userActionsManager, times(0)).incorrectPasskeyReceived(any(), any());
        }

        @Test
        void shouldEmitCloudwatchMetricsWhenAssertionSuccessful() {
            // Given
            AssertionResult mockAssertionResult = mock(AssertionResult.class);
            when(passkeyAssertionService.finishAssertion(any(), any(), any(), any()))
                    .thenReturn(Result.success(mockAssertionResult));

            // When
            handler.handleRequest(finishPasskeyAssertionRequest(), context);

            // Then
            var expectedMetricsDimensions = Map.of("Environment", ENV);

            verify(cloudwatchMetricsService, times(1))
                    .incrementCounter(PASSKEY_AUTHENTICATION_SUCCESSFUL, expectedMetricsDimensions);

            verify(cloudwatchMetricsService, times(1))
                    .incrementCounter(PASSKEY_VERIFICATION_SUCCESSFUL, expectedMetricsDimensions);

            verify(cloudwatchMetricsService, never())
                    .incrementCounter(eq(PASSKEY_VERIFICATION_FAILED), anyMap());
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
        void shouldReportIncorrectPasskeyReceivedWhenAssertionUnsuccessful() {
            // Given
            when(passkeyAssertionService.finishAssertion(any(), any(), any(), any()))
                    .thenReturn(
                            Result.failure(
                                    FinishPasskeyAssertionFailureReason.ASSERTION_FAILED_ERROR));

            // When
            handler.handleRequest(finishPasskeyAssertionRequest(), context);

            // Then
            verify(userActionsManager, times(1)).incorrectPasskeyReceived(any(), any());
            verify(userActionsManager, times(0)).correctPasskeyReceived(any(), any());
        }

        @Test
        void shouldReturn500WhenAssertionRequestDeserializationFails() {
            // Given
            when(passkeyAssertionService.finishAssertion(any(), any(), any(), any()))
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
            when(passkeyAssertionService.finishAssertion(any(), any(), any(), any()))
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
            when(passkeyAssertionService.finishAssertion(any(), any(), any(), any()))
                    .thenReturn(
                            Result.failure(
                                    FinishPasskeyAssertionFailureReason.ASSERTION_FAILED_ERROR));

            // When
            var response = handler.handleRequest(finishPasskeyAssertionRequest(), context);

            // Then
            assertThat(response, hasStatus(401));
            assertThat(response, hasJsonBody(ErrorResponse.PASSKEY_ASSERTION_FAILED));
        }

        @ParameterizedTest
        @EnumSource(FinishPasskeyAssertionFailureReason.class)
        void shouldEmitVerificationFailureMetricWhenAssertionFailsForAnyReason(
                FinishPasskeyAssertionFailureReason failureReason) {
            // Given
            when(passkeyAssertionService.finishAssertion(any(), any(), any(), any()))
                    .thenReturn(Result.failure(failureReason));

            // When
            handler.handleRequest(finishPasskeyAssertionRequest(), context);

            // Then
            var dimensionsForAuthenticationSuccessEvent = Map.of("Environment", ENV);
            var dimensionsForFailedEvent =
                    Map.ofEntries(
                            Map.entry("Environment", "test"),
                            Map.entry("FailureReason", failureReason.getValue()));

            verify(cloudwatchMetricsService)
                    .incrementCounter(
                            PASSKEY_AUTHENTICATION_SUCCESSFUL,
                            dimensionsForAuthenticationSuccessEvent);
            verify(cloudwatchMetricsService)
                    .incrementCounter(PASSKEY_VERIFICATION_FAILED, dimensionsForFailedEvent);

            verify(cloudwatchMetricsService, never())
                    .incrementCounter(eq(PASSKEY_VERIFICATION_SUCCESSFUL), anyMap());
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
