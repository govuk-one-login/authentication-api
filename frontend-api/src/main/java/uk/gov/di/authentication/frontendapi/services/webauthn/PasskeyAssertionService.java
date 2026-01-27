package uk.gov.di.authentication.frontendapi.services.webauthn;

import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.exception.AssertionFailedException;

import java.io.IOException;

public class PasskeyAssertionService {
    private final RelyingParty relyingParty;
    private final PasskeyJsonParser jsonParser;

    public PasskeyAssertionService(RelyingParty relyingParty, PasskeyJsonParser jsonParser) {
        this.relyingParty = relyingParty;
        this.jsonParser = jsonParser;
    }

    public AssertionResult finishAssertion(
            String assertionRequestJson, String publicKeyCredentialJson)
            throws IOException, AssertionFailedException {

        AssertionRequest assertionRequest = jsonParser.parseAssertionRequest(assertionRequestJson);
        PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
                credential = jsonParser.parsePublicKeyCredential(publicKeyCredentialJson);

        return relyingParty.finishAssertion(
                FinishAssertionOptions.builder()
                        .request(assertionRequest)
                        .response(credential)
                        .build());
    }
}
