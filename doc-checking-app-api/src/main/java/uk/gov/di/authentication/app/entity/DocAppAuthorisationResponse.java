package uk.gov.di.authentication.app.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class DocAppAuthorisationResponse {

    @JsonProperty("redirectUri")
    @SerializedName("redirectUri")
    @Expose
    private String redirectUri;

    public DocAppAuthorisationResponse(
            @JsonProperty(required = true, value = "redirectUri") String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getRedirectUri() {
        return redirectUri;
    }
}
