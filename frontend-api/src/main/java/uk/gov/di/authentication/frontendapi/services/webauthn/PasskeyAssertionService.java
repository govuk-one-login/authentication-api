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
import uk.gov.di.authentication.frontendapi.entity.FinishPasskeyAssertionFailureReason;
import uk.gov.di.authentication.shared.entity.Result;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

public class PasskeyAssertionService {
    private final RelyingParty relyingParty;
    private final PasskeyJsonParser jsonParser;
    private static final Logger LOG = LogManager.getLogger(PasskeyAssertionService.class);

    public PasskeyAssertionService(RelyingParty relyingParty, PasskeyJsonParser jsonParser) {
        this.relyingParty = relyingParty;
        this.jsonParser = jsonParser;
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
            AssertionRequest assertionRequest, String publicKeyCredentialJson) {
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

        return Result.success(assertionResult);
    }
}
