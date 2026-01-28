package uk.gov.di.authentication.frontendapi.services.webauthn;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;

import java.io.IOException;

public class DefaultPasskeyJsonParser implements PasskeyJsonParser {
    @Override
    public AssertionRequest parseAssertionRequest(String json) throws JsonProcessingException {
        return AssertionRequest.fromJson(json);
    }

    @Override
    public PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
            parsePublicKeyCredential(String json) throws IOException {
        return PublicKeyCredential.parseAssertionResponseJson(json);
    }
}
