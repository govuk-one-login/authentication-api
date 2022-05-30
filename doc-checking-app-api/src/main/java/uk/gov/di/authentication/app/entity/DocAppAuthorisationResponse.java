package uk.gov.di.authentication.app.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class DocAppAuthorisationResponse {

    @SerializedName("redirectUri")
    @Expose
    private String redirectUri;

    public DocAppAuthorisationResponse(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getRedirectUri() {
        return redirectUri;
    }
}
