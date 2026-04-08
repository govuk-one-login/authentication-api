package uk.gov.di.authentication.frontendapi.services.webauthn;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;

import java.io.IOException;

public interface PasskeyJsonParser {
    AssertionRequest parseAssertionRequest(String json) throws JsonProcessingException;

    PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
            parsePublicKeyCredential(String json) throws IOException;
}
