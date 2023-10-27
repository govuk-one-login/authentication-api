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
    private List<String> claims;

    @SerializedName("rp-sector-uri")
    @Expose
    @Required
    private String sectorIdentifier;

    @SerializedName("is-new-account")
    @Expose
    @Required
    private boolean isNewAccount;

    public AuthCodeRequest(
            String redirectUri,
            String state,
            List<String> claims,
            String sectorIdentifier,
            boolean isNewAccount) {
        this.redirectUri = redirectUri;
        this.state = state;
        this.claims = claims;
        this.sectorIdentifier = sectorIdentifier;
        this.isNewAccount = isNewAccount;
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

    public String getSectorIdentifier() {
        return sectorIdentifier;
    }

    public void setSectorIdentifier(String sectorIdentifier) {
        this.sectorIdentifier = sectorIdentifier;
    }

    public boolean isNewAccount() {
        return isNewAccount;
    }

    public void setNewAccount(boolean newAccount) {
        isNewAccount = newAccount;
    }
}
