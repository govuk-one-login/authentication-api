package uk.gov.di.authentication.frontendapi.services.webauthn;

import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.AssertionFailedException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.auditevents.entity.AuthPasskeyVerificationFailed;
import uk.gov.di.authentication.auditevents.entity.AuthPasskeyVerificationSuccessful;
import uk.gov.di.authentication.auditevents.entity.shared.passkeys.PasskeyAllowCredentials;
import uk.gov.di.authentication.auditevents.entity.shared.passkeys.PasskeyDetail;
import uk.gov.di.authentication.auditevents.services.StructuredAuditService;
import uk.gov.di.authentication.frontendapi.entity.FinishPasskeyAssertionFailureReason;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.List;
import java.util.Optional;

import static uk.gov.di.authentication.frontendapi.helpers.PasskeyAuditExtensionsHelper.passkeyAllowedCredentialsFrom;
import static uk.gov.di.authentication.frontendapi.helpers.PasskeyAuditExtensionsHelper.passkeyCredentialDeviceTypeFrom;
import static uk.gov.di.authentication.frontendapi.helpers.PasskeyAuditExtensionsHelper.userVerificationStringFrom;

public class PasskeyAssertionService {
    private final RelyingParty relyingParty;
    private final PasskeyJsonParser jsonParser;
    private static final Logger LOG = LogManager.getLogger(PasskeyAssertionService.class);
    private final StructuredAuditService structuredAuditService;

    public PasskeyAssertionService(
            RelyingParty relyingParty,
            PasskeyJsonParser jsonParser,
            StructuredAuditService structuredAuditService) {
        this.relyingParty = relyingParty;
        this.jsonParser = jsonParser;
        this.structuredAuditService = structuredAuditService;
    }

    public AssertionRequest startAssertion(String publicSubjectId) {
        var userHandle = new ByteArray(publicSubjectId.getBytes(StandardCharsets.UTF_8));
        return relyingParty.startAssertion(
                StartAssertionOptions.builder()
                        .userHandle(Optional.of(userHandle))
                        .userVerification(UserVerificationRequirement.REQUIRED)
                        .build());
    }

    public Result<FinishPasskeyAssertionFailureReason, AssertionResult> finishAssertion(
            String assertionRequestJson,
            String publicKeyCredentialJson,
            AuditContext auditContext) {
        PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
                credential;
        try {
            credential = jsonParser.parsePublicKeyCredential(publicKeyCredentialJson);
        } catch (Exception e) {
            var failureReason = "Public key credential in request failed to parse";
            emitAuthPasskeyVerificationFailedEvent(auditContext, failureReason, Optional.empty());
            return Result.failure(FinishPasskeyAssertionFailureReason.PARSING_PKC_ERROR);
        }

        AssertionRequest assertionRequest;
        try {
            assertionRequest = jsonParser.parseAssertionRequest(assertionRequestJson);
        } catch (Exception e) {
            var failureReason = "Assertion request stored in session failed to parse";
            emitAuthPasskeyVerificationFailedEvent(
                    auditContext, failureReason, Optional.of(credential));
            return Result.failure(
                    FinishPasskeyAssertionFailureReason.PARSING_ASSERTION_REQUEST_ERROR);
        }

        AssertionResult assertionResult;
        try {
            assertionResult =
                    relyingParty.finishAssertion(
                            FinishAssertionOptions.builder()
                                    .request(assertionRequest)
                                    .response(credential)
                                    .build());
        } catch (AssertionFailedException e) {
            LOG.error("Passkey assertion unexpectedly failed with error: {}", e.getMessage());
            emitAuthPasskeyVerificationFailedEventForAssertionError(
                    auditContext, assertionRequest, credential, e);
            return Result.failure(FinishPasskeyAssertionFailureReason.ASSERTION_FAILED_ERROR);
        }

        if (!assertionResult.isSuccess()) {
            LOG.warn("Passkey assertion unsuccessful");
            emitAuthPasskeyVerificationFailedEvent(
                    auditContext, assertionRequest, assertionResult, credential);
            return Result.failure(FinishPasskeyAssertionFailureReason.ASSERTION_FAILED_ERROR);
        }

        emitAuthPasskeyVerificationSuccessEvent(
                auditContext, assertionRequest, assertionResult, credential);

        return Result.success(assertionResult);
    }

    private void emitAuthPasskeyVerificationFailedEvent(
            AuditContext auditContext,
            String failureReason,
            Optional<
                            PublicKeyCredential<
                                    AuthenticatorAssertionResponse,
                                    ClientAssertionExtensionOutputs>>
                    maybePublicKeyCredential) {
        var passkeyDetail = PasskeyDetail.verificationCouldNotProceed(failureReason);
        var credentialId = maybePublicKeyCredential.map(c -> c.getId().getBase64Url()).orElse(null);
        emitVerificationFailedEvent(auditContext, null, credentialId, passkeyDetail);
    }

    private void emitAuthPasskeyVerificationFailedEventForAssertionError(
            AuditContext auditContext,
            AssertionRequest assertionRequest,
            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
                    publicKeyCredential,
            AssertionFailedException error) {
        var passkeyDetail =
                PasskeyDetail.verificationFailed(
                        userVerificationStringFrom(assertionRequest),
                        null,
                        null,
                        null,
                        String.format(
                                "Passkey finish assertion threw error: %s", error.getClass()));
        var alllowedCredentials = passkeyAllowedCredentialsFrom(assertionRequest);
        var credentialId = publicKeyCredential.getId().getBase64Url();
        emitVerificationFailedEvent(auditContext, alllowedCredentials, credentialId, passkeyDetail);
    }

    @SuppressWarnings("deprecation")
    private void emitAuthPasskeyVerificationFailedEvent(
            AuditContext auditContext,
            AssertionRequest assertionRequest,
            AssertionResult assertionResult,
            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
                    publicKeyCredential) {
        var passkeyDetail =
                PasskeyDetail.verificationFailed(
                        userVerificationStringFrom(assertionRequest),
                        assertionResult.getSignatureCount(),
                        assertionResult.isBackedUp(),
                        passkeyCredentialDeviceTypeFrom(assertionResult),
                        "Passkey assertion result was not successful");
        var alllowedCredentials = passkeyAllowedCredentialsFrom(assertionRequest);
        var credentialId = publicKeyCredential.getId().getBase64Url();
        emitVerificationFailedEvent(auditContext, alllowedCredentials, credentialId, passkeyDetail);
    }

    @SuppressWarnings("deprecation")
    private void emitAuthPasskeyVerificationSuccessEvent(
            AuditContext auditContext,
            AssertionRequest assertionRequest,
            AssertionResult assertionResult,
            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
                    publicKeyCredential) {
        var passkeyDetail =
                PasskeyDetail.verificationSuccessful(
                        userVerificationStringFrom(assertionRequest),
                        assertionResult.getSignatureCount(),
                        assertionResult.isBackedUp(),
                        passkeyCredentialDeviceTypeFrom(assertionResult));
        var event =
                AuthPasskeyVerificationSuccessful.create(
                        auditContext,
                        JourneyType.SIGN_IN,
                        passkeyAllowedCredentialsFrom(assertionRequest),
                        passkeyDetail,
                        publicKeyCredential.getId().getBase64Url(),
                        Clock.systemUTC());
        structuredAuditService.submitAuditEvent(event);
    }

    private void emitVerificationFailedEvent(
            AuditContext auditContext,
            List<PasskeyAllowCredentials> allowedCredentials,
            String credentialId,
            PasskeyDetail passkeyDetail) {
        var event =
                AuthPasskeyVerificationFailed.create(
                        auditContext,
                        JourneyType.SIGN_IN,
                        allowedCredentials,
                        credentialId,
                        passkeyDetail,
                        Clock.systemUTC());
        structuredAuditService.submitAuditEvent(event);
    }
}
