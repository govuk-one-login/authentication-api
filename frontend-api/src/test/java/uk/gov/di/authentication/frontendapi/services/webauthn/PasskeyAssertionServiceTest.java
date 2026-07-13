package uk.gov.di.authentication.frontendapi.services.webauthn;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.exception.AssertionFailedException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.auditevents.entity.AuthPasskeyVerificationFailed;
import uk.gov.di.authentication.auditevents.entity.AuthPasskeyVerificationSuccessful;
import uk.gov.di.authentication.auditevents.entity.StructuredAuditEvent;
import uk.gov.di.authentication.auditevents.entity.shared.passkeys.PasskeyAllowCredentials;
import uk.gov.di.authentication.auditevents.entity.shared.passkeys.PasskeyDetail;
import uk.gov.di.authentication.auditevents.entity.shared.passkeys.RestrictedPasskeySection;
import uk.gov.di.authentication.auditevents.services.StructuredAuditService;
import uk.gov.di.authentication.frontendapi.entity.FinishPasskeyAssertionFailureReason;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.PUBLIC_SUBJECT_ID;

class PasskeyAssertionServiceTest {
    private final RelyingParty relyingParty = mock(RelyingParty.class);
    private final PasskeyJsonParser jsonParser = mock(PasskeyJsonParser.class);
    private PasskeyAssertionService passkeyAssertionService;
    private static final String CREDENTIAL_ID = "Q6pkKSucKCqDzOuFky3pQAA";
    private static final StructuredAuditService structuredAuditService =
            mock(StructuredAuditService.class);
    private static final String VERIFICATION_FAILED_EVENT_NAME = "AUTH_PASSKEY_VERIFICATION_FAILED";
    private static final AuditContext AUDIT_CONTEXT =
            AuditContext.emptyAuditContext().withEmail(EMAIL);

    @BeforeEach
    void setup() {
        passkeyAssertionService =
                new PasskeyAssertionService(relyingParty, jsonParser, structuredAuditService);
    }

    @AfterEach
    void tearDown() {
        reset(structuredAuditService, jsonParser, relyingParty);
    }

    @Nested
    class StartAssertion {
        @Nested
        class Success {
            @Test
            void shouldReturnAssertionRequestIfRelyingPartyStartAssertionSucceeds() {
                // Given
                final Long ONE_HOUR_IN_MILLISECONDS = 3_600_000L;
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
                                .timeout(ONE_HOUR_IN_MILLISECONDS)
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
            void shouldReturnAssertionResultIfAssertionSucceeded()
                    throws IOException, AssertionFailedException, Base64UrlException {
                // Given
                var assertionRequest = setupAssertionRequest();
                when(jsonParser.parseAssertionRequest(any())).thenReturn(assertionRequest);
                var publicKeyCredential = setupPublicKeyCredential(CREDENTIAL_ID);
                when(jsonParser.parsePublicKeyCredential(any())).thenReturn(publicKeyCredential);
                AssertionResult mockAssertionResult = setupAnySuccessfulMockAssertionResult();
                when(mockAssertionResult.isSuccess()).thenReturn(true);
                when(relyingParty.finishAssertion(any())).thenReturn(mockAssertionResult);

                // When
                AssertionResult actualAssertionResult =
                        passkeyAssertionService.finishAssertion("", "", AUDIT_CONTEXT).getSuccess();

                // Then
                assertEquals(actualAssertionResult, mockAssertionResult);
            }

            @Test
            void shouldEmitAuditEventIfAssertionSucceeded()
                    throws IOException, AssertionFailedException, Base64UrlException {
                // Given
                var signCount = 10;
                var isBackedUp = false;
                var isBackupEligible = true;
                var userVerification = UserVerificationRequirement.REQUIRED;
                var assertionIsSuccess = true;
                var allowedCredentialsMap = Map.of(CREDENTIAL_ID, "BLE");

                var assertionRequest =
                        setupAssertionRequest(allowedCredentialsMap, userVerification);
                var publicKeyCredential = setupPublicKeyCredential(CREDENTIAL_ID);
                var assertionResult =
                        setupMockAssertionResult(
                                signCount, isBackupEligible, isBackedUp, assertionIsSuccess);

                when(jsonParser.parseAssertionRequest(any())).thenReturn(assertionRequest);
                when(jsonParser.parsePublicKeyCredential(any())).thenReturn(publicKeyCredential);
                when(relyingParty.finishAssertion(any())).thenReturn(assertionResult);

                // When
                passkeyAssertionService.finishAssertion("", "", AUDIT_CONTEXT).getSuccess();

                // Then
                var argCaptor = ArgumentCaptor.forClass(StructuredAuditEvent.class);

                verify(structuredAuditService).submitAuditEvent(argCaptor.capture());
                var capturedAuditEvent = argCaptor.getValue();

                assertEquals(
                        "AUTH_PASSKEY_VERIFICATION_SUCCESSFUL", capturedAuditEvent.eventName());

                var authPasskeyVerificationSuccessful =
                        (AuthPasskeyVerificationSuccessful) capturedAuditEvent;

                assertEquals(EMAIL, authPasskeyVerificationSuccessful.user().email());

                var expectedPasskeyDetail =
                        PasskeyDetail.verificationSuccessful(
                                userVerification.getValue(), signCount, isBackedUp, "multi-device");
                assertEquals(
                        expectedPasskeyDetail,
                        authPasskeyVerificationSuccessful.extensions().passkey());

                var restrictedPasskeySection =
                        new RestrictedPasskeySection(
                                List.of(new PasskeyAllowCredentials(CREDENTIAL_ID, List.of("BLE"))),
                                CREDENTIAL_ID);
                assertEquals(
                        restrictedPasskeySection,
                        authPasskeyVerificationSuccessful.restricted().passkey());
            }
        }

        @Nested
        class Error {
            @Test
            void shouldFailWithParsingAssertionRequestErrorWhenAssertionRequestJsonParsingFails()
                    throws IOException, Base64UrlException {
                // Given
                var pkc = setupPublicKeyCredential(CREDENTIAL_ID);
                when(jsonParser.parsePublicKeyCredential(any())).thenReturn(pkc);
                when(jsonParser.parseAssertionRequest(any()))
                        .thenThrow(JsonProcessingException.class);

                // When
                FinishPasskeyAssertionFailureReason actualFailureReason =
                        passkeyAssertionService.finishAssertion("", "", AUDIT_CONTEXT).getFailure();

                // Then
                assertEquals(
                        FinishPasskeyAssertionFailureReason.PARSING_ASSERTION_REQUEST_ERROR,
                        actualFailureReason);

                verifyAuditEventEmittedWithName(VERIFICATION_FAILED_EVENT_NAME);
            }

            @Test
            void shouldEmitAuditEventWhenAssertionRequestParsingFails()
                    throws IOException, Base64UrlException {
                // Given
                var pkc = setupPublicKeyCredential(CREDENTIAL_ID);
                when(jsonParser.parsePublicKeyCredential(any())).thenReturn(pkc);
                when(jsonParser.parseAssertionRequest(any()))
                        .thenThrow(JsonProcessingException.class);

                // When
                passkeyAssertionService.finishAssertion("", "", AUDIT_CONTEXT).getFailure();

                // Then
                var expectedPasskeyDetail =
                        PasskeyDetail.verificationCouldNotProceed(
                                "Assertion request stored in session failed to parse");
                var expectedRestrictedPasskeySection =
                        new RestrictedPasskeySection(null, CREDENTIAL_ID);
                verifyVerificationFailedAuditEventEmitted(
                        expectedPasskeyDetail, expectedRestrictedPasskeySection);
            }

            @Test
            void shouldFailWithParsingPkcErrorWhenPKCJsonParsingFails() throws IOException {
                // Given
                when(jsonParser.parseAssertionRequest(any()))
                        .thenReturn(mock(AssertionRequest.class));
                when(jsonParser.parsePublicKeyCredential(any())).thenThrow(IOException.class);

                // When
                FinishPasskeyAssertionFailureReason actualFailureReason =
                        passkeyAssertionService.finishAssertion("", "", AUDIT_CONTEXT).getFailure();

                // Then
                assertEquals(
                        FinishPasskeyAssertionFailureReason.PARSING_PKC_ERROR, actualFailureReason);
                verifyAuditEventEmittedWithName(VERIFICATION_FAILED_EVENT_NAME);
            }

            @Test
            void shouldEmitRelevantAuditEventWhenPKCParsingFails() throws IOException {
                // Given
                when(jsonParser.parseAssertionRequest(any()))
                        .thenReturn(mock(AssertionRequest.class));
                when(jsonParser.parsePublicKeyCredential(any())).thenThrow(IOException.class);

                // When
                passkeyAssertionService.finishAssertion("", "", AUDIT_CONTEXT).getFailure();

                // Then
                var expectedPasskeyDetail =
                        PasskeyDetail.verificationCouldNotProceed(
                                "Public key credential in request failed to parse");
                var expectedRestrictedPasskeySection = new RestrictedPasskeySection(null, null);
                verifyVerificationFailedAuditEventEmitted(
                        expectedPasskeyDetail, expectedRestrictedPasskeySection);
            }

            @Test
            @SuppressWarnings("unchecked")
            void shouldFailWithAssertionFailedErrorWhenAssertionFails()
                    throws IOException, AssertionFailedException, Base64UrlException {
                // Given
                var assertionRequest = setupAssertionRequest();
                var credential = setupPublicKeyCredential(CREDENTIAL_ID);
                when(jsonParser.parseAssertionRequest(any())).thenReturn(assertionRequest);
                when(jsonParser.parsePublicKeyCredential(any())).thenReturn(credential);
                when(relyingParty.finishAssertion(any())).thenThrow(AssertionFailedException.class);

                // When
                FinishPasskeyAssertionFailureReason actualFailureReason =
                        passkeyAssertionService.finishAssertion("", "", AUDIT_CONTEXT).getFailure();

                // Then
                assertEquals(
                        FinishPasskeyAssertionFailureReason.ASSERTION_FAILED_ERROR,
                        actualFailureReason);
                verifyAuditEventEmittedWithName(VERIFICATION_FAILED_EVENT_NAME);
            }

            @Test
            void shouldEmitAnAuditEventWhenAssertionThrowsError()
                    throws IOException, AssertionFailedException, Base64UrlException {
                // Given
                var userVerification = UserVerificationRequirement.PREFERRED;
                var allowedCredentialsMap = Map.of(CREDENTIAL_ID, "BLE");

                var assertionRequest =
                        setupAssertionRequest(allowedCredentialsMap, userVerification);
                var publicKeyCredential = setupPublicKeyCredential(CREDENTIAL_ID);
                when(jsonParser.parseAssertionRequest(any())).thenReturn(assertionRequest);
                when(jsonParser.parsePublicKeyCredential(any())).thenReturn(publicKeyCredential);
                when(relyingParty.finishAssertion(any())).thenThrow(AssertionFailedException.class);

                // When
                passkeyAssertionService.finishAssertion("", "", AUDIT_CONTEXT).getFailure();

                // Then
                var expectedFailureReason =
                        "Passkey finish assertion threw error: class com.yubico.webauthn.exception.AssertionFailedException";
                var expectedPasskeyDetail =
                        PasskeyDetail.verificationFailed(
                                userVerification.getValue(),
                                null,
                                null,
                                null,
                                expectedFailureReason);

                var expectedRestrictedPasskeySection =
                        new RestrictedPasskeySection(
                                List.of(new PasskeyAllowCredentials(CREDENTIAL_ID, List.of("BLE"))),
                                CREDENTIAL_ID);

                verifyVerificationFailedAuditEventEmitted(
                        expectedPasskeyDetail, expectedRestrictedPasskeySection);
            }

            @Test
            @SuppressWarnings("unchecked")
            void shouldFailWithAssertionFailedErrorWhenAssertionIsNotSuccessful()
                    throws IOException, AssertionFailedException, Base64UrlException {
                // Given
                var assertionRequest = setupAssertionRequest();
                var publicKeyCredential = setupPublicKeyCredential(CREDENTIAL_ID);
                var assertionResult = setupAnyFailureMockAssertionResult();
                when(relyingParty.finishAssertion(any())).thenReturn(assertionResult);
                when(jsonParser.parseAssertionRequest(any())).thenReturn(assertionRequest);
                when(jsonParser.parsePublicKeyCredential(any())).thenReturn(publicKeyCredential);

                // When
                FinishPasskeyAssertionFailureReason actualFailureReason =
                        passkeyAssertionService.finishAssertion("", "", AUDIT_CONTEXT).getFailure();

                // Then
                assertEquals(
                        FinishPasskeyAssertionFailureReason.ASSERTION_FAILED_ERROR,
                        actualFailureReason);
                verifyAuditEventEmittedWithName(VERIFICATION_FAILED_EVENT_NAME);
            }

            @Test
            @SuppressWarnings("unchecked")
            void shouldEmitVerificationFailedAuditEventWhenAssertionIsNotSuccessful()
                    throws IOException, AssertionFailedException, Base64UrlException {
                // Given

                var assertionIsSuccess = false;
                var signCount = 10L;
                var isBackedUp = false;
                var isBackupEligible = false;
                var userVerification = UserVerificationRequirement.PREFERRED;
                var allowedCredentialsMap = Map.of(CREDENTIAL_ID, "BLE");

                var assertionRequest =
                        setupAssertionRequest(allowedCredentialsMap, userVerification);
                var publicKeyCredential = setupPublicKeyCredential(CREDENTIAL_ID);
                var assertionResult =
                        setupMockAssertionResult(
                                signCount, isBackupEligible, isBackedUp, assertionIsSuccess);
                when(relyingParty.finishAssertion(any())).thenReturn(assertionResult);
                when(jsonParser.parseAssertionRequest(any())).thenReturn(assertionRequest);
                when(jsonParser.parsePublicKeyCredential(any())).thenReturn(publicKeyCredential);

                // When
                passkeyAssertionService.finishAssertion("", "", AUDIT_CONTEXT).getFailure();

                // Then
                var expectedPasskeyDetail =
                        PasskeyDetail.verificationFailed(
                                userVerification.getValue(),
                                signCount,
                                isBackedUp,
                                "single-device",
                                "Passkey assertion result was not successful");

                var expectedRestrictedPasskeySection =
                        new RestrictedPasskeySection(
                                List.of(new PasskeyAllowCredentials(CREDENTIAL_ID, List.of("BLE"))),
                                CREDENTIAL_ID);
                verifyVerificationFailedAuditEventEmitted(
                        expectedPasskeyDetail, expectedRestrictedPasskeySection);
            }
        }

        private void verifyVerificationFailedAuditEventEmitted(
                PasskeyDetail expectedPasskeyDetail,
                RestrictedPasskeySection expectedRestrictedPasskeySection) {
            var argCaptor = ArgumentCaptor.forClass(StructuredAuditEvent.class);

            verify(structuredAuditService).submitAuditEvent(argCaptor.capture());
            var capturedAuditEvent = argCaptor.getValue();

            assertEquals(VERIFICATION_FAILED_EVENT_NAME, capturedAuditEvent.eventName());

            var authPasskeyVerificationFailed = (AuthPasskeyVerificationFailed) capturedAuditEvent;

            assertEquals(EMAIL, authPasskeyVerificationFailed.user().email());

            assertEquals(
                    expectedPasskeyDetail, authPasskeyVerificationFailed.extensions().passkey());

            assertEquals(
                    expectedRestrictedPasskeySection,
                    authPasskeyVerificationFailed.restricted().passkey());
        }
    }

    private static AssertionResult setupAnySuccessfulMockAssertionResult() {
        return setupMockAssertionResult(10, false, false, true);
    }

    private static AssertionResult setupAnyFailureMockAssertionResult() {
        return setupMockAssertionResult(10, false, false, false);
    }

    private void verifyAuditEventEmittedWithName(String expectedName) {
        verify(structuredAuditService)
                .submitAuditEvent(argThat(event -> event.eventName().equals(expectedName)));
    }

    @SuppressWarnings("deprecation")
    private static AssertionResult setupMockAssertionResult(
            long signCount, boolean isBackupEligible, boolean isBackedUp, boolean isSuccess) {
        var mock = mock(AssertionResult.class);
        when(mock.getSignatureCount()).thenReturn(signCount);
        when(mock.isBackupEligible()).thenReturn(isBackupEligible);
        when(mock.isBackedUp()).thenReturn(isBackedUp);
        when(mock.isSuccess()).thenReturn(isSuccess);
        return mock;
    }

    private static AssertionRequest setupAssertionRequest(
            Map<String, String> credentials,
            UserVerificationRequirement userVerificationRequirement) {
        var assertionRequest = mock(AssertionRequest.class);
        var publicKeyCredentialRequestOptions = mock(PublicKeyCredentialRequestOptions.class);
        var allPublicKeyCredentialDescriptors = new ArrayList<PublicKeyCredentialDescriptor>();
        credentials.forEach(
                (k, v) -> {
                    try {
                        var descriptor =
                                PublicKeyCredentialDescriptor.builder()
                                        .id(ByteArray.fromBase64Url(CREDENTIAL_ID))
                                        .transports(Set.of(AuthenticatorTransport.of(v)))
                                        .build();
                        allPublicKeyCredentialDescriptors.add(descriptor);
                    } catch (Base64UrlException e) {
                        throw new RuntimeException(e);
                    }
                });
        when(publicKeyCredentialRequestOptions.getAllowCredentials())
                .thenReturn(Optional.of(allPublicKeyCredentialDescriptors));
        when(publicKeyCredentialRequestOptions.getUserVerification())
                .thenReturn(Optional.of(userVerificationRequirement));
        when(assertionRequest.getPublicKeyCredentialRequestOptions())
                .thenReturn(publicKeyCredentialRequestOptions);

        return assertionRequest;
    }

    private static AssertionRequest setupAssertionRequest() {
        var assertionRequest = mock(AssertionRequest.class);
        var publicKeyCredentialRequestOptions = mock(PublicKeyCredentialRequestOptions.class);
        when(publicKeyCredentialRequestOptions.getAllowCredentials()).thenReturn(Optional.empty());
        when(publicKeyCredentialRequestOptions.getUserVerification())
                .thenReturn(Optional.of(UserVerificationRequirement.REQUIRED));
        when(assertionRequest.getPublicKeyCredentialRequestOptions())
                .thenReturn(publicKeyCredentialRequestOptions);

        return assertionRequest;
    }

    private static PublicKeyCredential<
                    AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
            setupPublicKeyCredential(String credentialId) throws Base64UrlException {
        var credential = mock(PublicKeyCredential.class);
        when(credential.getId()).thenReturn(ByteArray.fromBase64Url(credentialId));
        return credential;
    }
}
