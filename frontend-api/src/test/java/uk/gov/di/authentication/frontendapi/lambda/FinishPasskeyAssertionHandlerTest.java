package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.data.exception.Base64UrlException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import uk.gov.di.authentication.auditevents.entity.AuthPasskeyVerificationSuccessful;
import uk.gov.di.authentication.auditevents.entity.StructuredAuditEvent;
import uk.gov.di.authentication.auditevents.entity.shared.passkeys.PasskeyAllowCredentials;
import uk.gov.di.authentication.auditevents.entity.shared.passkeys.PasskeyDetail;
import uk.gov.di.authentication.auditevents.services.StructuredAuditService;
import uk.gov.di.authentication.frontendapi.entity.FinishPasskeyAssertionFailureReason;
import uk.gov.di.authentication.frontendapi.services.webauthn.PasskeyAssertionService;
import uk.gov.di.authentication.frontendapi.services.webauthn.PasskeyJsonParser;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.userpermissions.UserActionsManager;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
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
    private final StructuredAuditService structuredAuditService =
            mock(StructuredAuditService.class);
    private final PasskeyJsonParser passkeyJsonParser = mock(PasskeyJsonParser.class);
    private FinishPasskeyAssertionHandler handler;
    private final AuthSessionItem authSession = new AuthSessionItem().withSessionId(SESSION_ID);

    private static final String CREDENTIAL_ID = "Q6pkKSucKCqDzOuFky3pQAA";

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
                        passkeyAssertionService,
                        userActionsManager,
                        structuredAuditService,
                        passkeyJsonParser);
    }

    @Nested
    class Success {

        @BeforeEach
        void setupMockData() throws IOException, Base64UrlException {
            setupSuccessfulRequestParsing();
        }

        @Test
        void shouldReturn200WhenPasskeyAssertionSuccessful() {
            // Given
            var assertionResult = setupAnyAssertionResult();
            when(passkeyAssertionService.finishAssertion(any(), any()))
                    .thenReturn(Result.success(assertionResult));

            // When
            var response = handler.handleRequest(finishPasskeyAssertionRequest(), context);

            // Then
            assertThat(response, hasStatus(200));
        }

        @Test
        void shouldReportCorrectPasskeyReceivedWhenAssertionSuccessful() {
            // Given
            var assertionResult = setupAnyAssertionResult();
            when(passkeyAssertionService.finishAssertion(any(), any()))
                    .thenReturn(Result.success(assertionResult));

            // When
            handler.handleRequest(finishPasskeyAssertionRequest(), context);

            // Then
            verify(userActionsManager, times(1)).correctPasskeyReceived(any(), any());
            verify(userActionsManager, times(0)).incorrectPasskeyReceived(any(), any());
        }

        @Test
        void shouldEmitVerificationSuccessAuditEventWhenAssertionSuccessful() {
            // Given
            var signCount = 10;
            var isBackedUp = false;
            var isBackupEligible = true;
            var userVerification = UserVerificationRequirement.REQUIRED;
            var assertionResult = setupMockAssertionResult(signCount, isBackupEligible, isBackedUp);
            when(passkeyAssertionService.finishAssertion(any(), any()))
                    .thenReturn(Result.success(assertionResult));

            // When
            handler.handleRequest(finishPasskeyAssertionRequest(), context);

            // Then
            var argCaptor = ArgumentCaptor.forClass(StructuredAuditEvent.class);

            verify(structuredAuditService).submitAuditEvent(argCaptor.capture());
            var capturedAuditEvent = argCaptor.getValue();

            assertEquals("AUTH_PASSKEY_VERIFICATION_SUCCESSFUL", capturedAuditEvent.eventName());

            var authPasskeyVerificationSuccessful =
                    (AuthPasskeyVerificationSuccessful) capturedAuditEvent;

            var expectedPasskeyDetail =
                    PasskeyDetail.verificationSuccessful(
                            userVerification.getValue(), signCount, isBackedUp, "multi-device");
            assertEquals(
                    expectedPasskeyDetail,
                    authPasskeyVerificationSuccessful.extensions().passkey());

            assertEquals(
                    CREDENTIAL_ID,
                    authPasskeyVerificationSuccessful.restricted().passkeyCredentialId());
            var expectedRestrictedPasskeySection =
                    new AuthPasskeyVerificationSuccessful.RestrictedPasskeySection(
                            List.of(new PasskeyAllowCredentials(CREDENTIAL_ID, List.of("usb"))));
            assertEquals(
                    expectedRestrictedPasskeySection,
                    authPasskeyVerificationSuccessful.restricted().passkey());
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
            verify(structuredAuditService, never()).submitAuditEvent(any());
        }
    }

    @Nested
    class Error {
        @Test
        void shouldReturn500WhenAssertionRequestDeserializationFails() throws IOException {
            // Given
            when(passkeyJsonParser.parseAssertionRequest(any()))
                    .thenThrow(JsonProcessingException.class);
            // These should not be called, but set it up anyway to ensure the test is passing for
            // the
            // right reasons
            when(passkeyJsonParser.parsePublicKeyCredential(any()))
                    .thenReturn(mock(PublicKeyCredential.class));
            when(passkeyAssertionService.finishAssertion(any(), any()))
                    .thenReturn(Result.success(mock(AssertionResult.class)));

            // When
            var response = handler.handleRequest(finishPasskeyAssertionRequest(), context);

            // Then
            assertThat(response, hasStatus(500));
            assertThat(response, hasJsonBody(ErrorResponse.UNEXPECTED_INTERNAL_API_ERROR));
            verify(structuredAuditService, never()).submitAuditEvent(any());
        }

        @Test
        void shouldReturn401WhenAssertionReturnsAssertionResultFailure()
                throws Base64UrlException, IOException {
            // Given
            setupSuccessfulRequestParsing();
            var assertionResult = mock(AssertionResult.class);
            when(assertionResult.isSuccess()).thenReturn(false);
            when(passkeyAssertionService.finishAssertion(any(), any()))
                    .thenReturn(Result.success(assertionResult));

            // When
            var result = handler.handleRequest(finishPasskeyAssertionRequest(), context);

            // Then
            assertEquals(401, result.getStatusCode());
        }

        @Test
        void shouldReportIncorrectPasskeyReceivedWhenAssertionReturnsAssertionResultFailure()
                throws Base64UrlException, IOException {
            // Given
            setupSuccessfulRequestParsing();
            var assertionResult = mock(AssertionResult.class);
            when(assertionResult.isSuccess()).thenReturn(false);
            when(passkeyAssertionService.finishAssertion(any(), any()))
                    .thenReturn(Result.success(assertionResult));

            // When
            handler.handleRequest(finishPasskeyAssertionRequest(), context);

            // Then
            verify(userActionsManager, times(1)).incorrectPasskeyReceived(any(), any());
            verify(userActionsManager, times(0)).correctPasskeyReceived(any(), any());
        }

        @Test
        void shouldReportIncorrectPasskeyReceivedWhenAssertionUnsuccessful() {
            // Given
            when(passkeyAssertionService.finishAssertion(any(), any()))
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
        void shouldReturn400WhenPKCDeserializationFails() throws IOException {
            // Given
            when(passkeyJsonParser.parseAssertionRequest(any()))
                    .thenReturn(mock(AssertionRequest.class));
            when(passkeyJsonParser.parsePublicKeyCredential(any()))
                    .thenThrow(JsonProcessingException.class);
            // This should not be called, but set it up anyway to ensure the test is passing for the
            // right reasons
            when(passkeyAssertionService.finishAssertion(any(), any()))
                    .thenReturn(Result.success(mock(AssertionResult.class)));

            // When
            var response = handler.handleRequest(finishPasskeyAssertionRequest(), context);

            // Then
            assertThat(response, hasStatus(400));
            assertThat(response, hasJsonBody(ErrorResponse.PASSKEY_ASSERTION_INVALID_PKC));
            verify(structuredAuditService, never()).submitAuditEvent(any());
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
    }

    private APIGatewayProxyRequestEvent finishPasskeyAssertionRequest(String body) {
        return new APIGatewayProxyRequestEvent()
                .withHeaders(VALID_HEADERS)
                .withBody(body)
                .withRequestContext(contextWithSourceIp(IP_ADDRESS));
    }

    private static AssertionResult setupAnyAssertionResult() {
        return setupMockAssertionResult(1, true, true);
    }

    @SuppressWarnings("deprecation")
    private static AssertionResult setupMockAssertionResult(
            long signCount, boolean isBackupEligible, boolean isBackedUp) {
        var mock = mock(AssertionResult.class);
        when(mock.getSignatureCount()).thenReturn(signCount);
        when(mock.isBackupEligible()).thenReturn(isBackupEligible);
        when(mock.isBackedUp()).thenReturn(isBackedUp);
        when(mock.isSuccess()).thenReturn(true);
        return mock;
    }

    private static AssertionRequest setupAssertionRequest() throws Base64UrlException {
        var assertionRequest = mock(AssertionRequest.class);
        var publicKeyCredentialRequestOptions = mock(PublicKeyCredentialRequestOptions.class);
        var credentialId = ByteArray.fromBase64Url(CREDENTIAL_ID);
        var descriptor =
                PublicKeyCredentialDescriptor.builder()
                        .id(credentialId)
                        .transports(Set.of(AuthenticatorTransport.USB))
                        .build();
        when(publicKeyCredentialRequestOptions.getUserVerification())
                .thenReturn(Optional.of(UserVerificationRequirement.REQUIRED));
        when(publicKeyCredentialRequestOptions.getAllowCredentials())
                .thenReturn(Optional.of(List.of(descriptor)));
        when(assertionRequest.getPublicKeyCredentialRequestOptions())
                .thenReturn(publicKeyCredentialRequestOptions);

        return assertionRequest;
    }

    private static PublicKeyCredential<
                    AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
            setupPublicKeyCredential(String credentialId) throws Base64UrlException {
        var credential = mock(PublicKeyCredential.class);
        when(credential.getId()).thenReturn(ByteArray.fromBase64Url(CREDENTIAL_ID));
        return credential;
    }

    private void setupSuccessfulRequestParsing() throws IOException, Base64UrlException {
        AssertionRequest assertionRequest = setupAssertionRequest();
        PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
                publicKeyCredential = setupPublicKeyCredential(CREDENTIAL_ID);
        when(passkeyJsonParser.parseAssertionRequest(any())).thenReturn(assertionRequest);
        when(passkeyJsonParser.parsePublicKeyCredential(any())).thenReturn(publicKeyCredential);
    }

    private APIGatewayProxyRequestEvent finishPasskeyAssertionRequest() {
        return finishPasskeyAssertionRequest(
                String.format(
                        """
            {"pkc": "{\\"id\\": \\"%s\\"}"}
            """,
                        CREDENTIAL_ID));
    }
}
