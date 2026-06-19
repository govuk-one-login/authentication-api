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
import uk.gov.di.authentication.auditevents.entity.AuthPasskeyVerificationSuccessful;
import uk.gov.di.authentication.auditevents.entity.shared.passkeys.PasskeyDetail;
import uk.gov.di.authentication.auditevents.services.StructuredAuditService;
import uk.gov.di.authentication.frontendapi.entity.FinishPasskeyAssertionFailureReason;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.services.AuditService;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Optional;

import static uk.gov.di.authentication.frontendapi.helpers.PasskeyAuditExtensionsHelper.passkeyAllowedCredentialsFrom;

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
            String assertionRequestJson, String publicKeyCredentialJson) {

        AssertionRequest assertionRequest;
        try {
            assertionRequest = jsonParser.parseAssertionRequest(assertionRequestJson);
        } catch (Exception e) {
            return Result.failure(
                    FinishPasskeyAssertionFailureReason.PARSING_ASSERTION_REQUEST_ERROR);
        }

        PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
                credential;
        try {
            credential = jsonParser.parsePublicKeyCredential(publicKeyCredentialJson);
        } catch (Exception e) {
            return Result.failure(FinishPasskeyAssertionFailureReason.PARSING_PKC_ERROR);
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
            return Result.failure(FinishPasskeyAssertionFailureReason.ASSERTION_FAILED_ERROR);
        }

        if (!assertionResult.isSuccess()) {
            LOG.warn("Passkey assertion unsuccessful");
            return Result.failure(FinishPasskeyAssertionFailureReason.ASSERTION_FAILED_ERROR);
        }

        //TODO pass in audit context to this function
        emitAuthPasskeyVerificationSuccessEvent(
                AuditContext.emptyAuditContext(), assertionRequest, assertionResult, credential);

        return Result.success(assertionResult);
    }

    @SuppressWarnings("deprecation")
    private void emitAuthPasskeyVerificationSuccessEvent(
            AuditContext auditContext,
            AssertionRequest assertionRequest,
            AssertionResult assertionResult,
            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
                    publicKeyCredential) {
        var passkeyAllowedCredentials = passkeyAllowedCredentialsFrom(assertionRequest);
        var userVerification =
                assertionRequest
                        .getPublicKeyCredentialRequestOptions()
                        .getUserVerification()
                        .map(UserVerificationRequirement::getValue)
                        .orElse(AuditService.UNKNOWN);
        var passkeyCredentialDeviceType =
                assertionResult.isBackupEligible() ? "multi-device" : "single-device";
        var passkeyDetail =
                PasskeyDetail.verificationSuccessful(
                        userVerification,
                        (int) assertionResult.getSignatureCount(), // TODO change to long
                        assertionResult.isBackedUp(),
                        passkeyCredentialDeviceType);
        var event =
                AuthPasskeyVerificationSuccessful.create(
                        auditContext,
                        JourneyType.SIGN_IN,
                        passkeyAllowedCredentials,
                        passkeyDetail,
                        publicKeyCredential.getId().getBase64Url(),
                        Clock.systemUTC());
        structuredAuditService.submitAuditEvent(event);
    }
}
