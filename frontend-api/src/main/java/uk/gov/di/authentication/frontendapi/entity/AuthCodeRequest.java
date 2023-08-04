package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public class AuthCodeRequest {

    @SerializedName("redirect-uri")
    @Expose
    @Required
    private String redirectUri;

    @SerializedName("state")
    @Expose
    @Required
    private String state;

    @SerializedName("requestedScopeClaims")
    @Expose
    @Required
    private String requestedScopeClaims;

    @SerializedName("email")
    @Expose
    @Required
    private String email;

    public AuthCodeRequest(
            String redirectUri, String state, String requestedScopeClaims, String email) {
        this.redirectUri = redirectUri;
        this.state = state;
        this.requestedScopeClaims = requestedScopeClaims;
        this.email = email;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getRequestedScopeClaims() {
        return requestedScopeClaims;
    }

    public void setRequestedScopeClaims(String requestedScopeClaims) {
        this.requestedScopeClaims = requestedScopeClaims;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}
