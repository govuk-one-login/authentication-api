package uk.gov.di.authentication.ipv.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.nimbusds.oauth2.sdk.id.State;
import uk.gov.di.authentication.shared.validation.Required;

import java.net.URI;

public class IdentityProgressResponse {

    @SerializedName("status")
    @Expose
    @Required
    private IdentityProgressStatus status;

    @SerializedName("client-name")
    @Expose
    @Required
    private String clientName;

    @SerializedName("redirect-uri")
    @Expose
    @Required
    private URI redirectUri;

    @SerializedName("state")
    @Expose
    @Required
    private State state;

    public IdentityProgressResponse() {}

    public IdentityProgressResponse(
            IdentityProgressStatus status, String clientName, URI redirectUri, State state) {
        this.status = status;
        this.clientName = clientName;
        this.redirectUri = redirectUri;
        this.state = state;
    }

    public IdentityProgressStatus getStatus() {
        return status;
    }

    public String getClientName() {
        return clientName;
    }

    public URI getRedirectUri() {
        return redirectUri;
    }

    public State getState() {
        return state;
    }
}
