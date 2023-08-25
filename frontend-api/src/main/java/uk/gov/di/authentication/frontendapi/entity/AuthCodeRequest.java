package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

import java.util.List;

public class AuthCodeRequest {

    @SerializedName("redirect-uri")
    @Expose
    @Required
    private String redirectUri;

    @SerializedName("state")
    @Expose
    @Required
    private String state;

    @SerializedName("claims")
    @Expose
    @Required
    private List<String> claims;

    @SerializedName("email")
    @Expose
    @Required
    private String email;

    public AuthCodeRequest(String redirectUri, String state, List<String> claims, String email) {
        this.redirectUri = redirectUri;
        this.state = state;
        this.claims = claims;
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

    public List<String> getClaims() {
        return claims;
    }

    public void setClaims(List<String> claims) {
        this.claims = claims;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}
