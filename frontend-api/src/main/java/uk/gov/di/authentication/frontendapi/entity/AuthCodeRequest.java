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

    public AuthCodeRequest(String redirectUri, String state, List<String> claims) {
        this.redirectUri = redirectUri;
        this.state = state;
        this.claims = claims;
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
}
