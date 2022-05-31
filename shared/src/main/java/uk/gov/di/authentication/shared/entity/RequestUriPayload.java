package uk.gov.di.authentication.shared.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import uk.gov.di.authentication.shared.validation.Required;

public class RequestUriPayload {

    @Expose
    @Required
    @SerializedName("clientRegistry")
    private ClientRegistry clientRegistry;

    @Expose
    @Required
    @SerializedName("authRequest")
    private AuthenticationRequest authRequest;

    public RequestUriPayload(ClientRegistry clientRegistry, AuthenticationRequest authRequest) {
        this.clientRegistry = clientRegistry;
        this.authRequest = authRequest;
    }

    public RequestUriPayload() {}

    public ClientRegistry getClientRegistry() {
        return clientRegistry;
    }

    public AuthenticationRequest getAuthRequest() {
        return authRequest;
    }
}
