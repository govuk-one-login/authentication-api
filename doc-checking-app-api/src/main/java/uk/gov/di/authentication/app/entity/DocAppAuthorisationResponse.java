package uk.gov.di.authentication.app.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class DocAppAuthorisationResponse {

    @JsonProperty("redirectUri")
    private String redirectUri;

    public DocAppAuthorisationResponse(
            @JsonProperty(required = true, value = "redirectUri") String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getRedirectUri() {
        return redirectUri;
    }
}
