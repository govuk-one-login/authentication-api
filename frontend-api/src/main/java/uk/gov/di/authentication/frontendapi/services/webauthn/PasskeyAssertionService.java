package uk.gov.di.authentication.frontendapi.services.webauthn;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.exception.AssertionFailedException;
import uk.gov.di.authentication.frontendapi.entity.FinishPasskeyAssertionFailureReason;
import uk.gov.di.authentication.shared.entity.Result;

import java.io.IOException;

public class PasskeyAssertionService {
    private final RelyingParty relyingParty;
    private final PasskeyJsonParser jsonParser;

    public PasskeyAssertionService(RelyingParty relyingParty, PasskeyJsonParser jsonParser) {
        this.relyingParty = relyingParty;
        this.jsonParser = jsonParser;
    }

    public Result<FinishPasskeyAssertionFailureReason, AssertionResult> finishAssertion(
            String assertionRequestJson, String publicKeyCredentialJson) {

        AssertionRequest assertionRequest;
        try {
            assertionRequest = jsonParser.parseAssertionRequest(assertionRequestJson);
        } catch (JsonProcessingException e) {
            return Result.failure(
                    FinishPasskeyAssertionFailureReason.PARSING_ASSERTION_REQUEST_ERROR);
        }

        PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
                credential;
        try {
            credential = jsonParser.parsePublicKeyCredential(publicKeyCredentialJson);
        } catch (IOException e) {
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
            return Result.failure(FinishPasskeyAssertionFailureReason.ASSERTION_FAILED_ERROR);
        }

        if (!assertionResult.isSuccess()) {
            return Result.failure(FinishPasskeyAssertionFailureReason.ASSERTION_FAILED_ERROR);
        }

        return Result.success(assertionResult);
    }
}
