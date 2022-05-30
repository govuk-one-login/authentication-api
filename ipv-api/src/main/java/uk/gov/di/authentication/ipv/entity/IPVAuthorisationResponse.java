package uk.gov.di.authentication.ipv.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public class IPVAuthorisationResponse {

    @SerializedName("redirectUri")
    @Expose
    @Required
    private String redirectUri;

    public IPVAuthorisationResponse() {}

    public IPVAuthorisationResponse(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getRedirectUri() {
        return redirectUri;
    }
}
