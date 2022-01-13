package uk.gov.di.authentication.ipv.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class IPVAuthorisationResponse {

    @JsonProperty("redirectUri")
    private String redirectUri;

    public IPVAuthorisationResponse(
            @JsonProperty(required = true, value = "redirectUri") String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getRedirectUri() {
        return redirectUri;
    }
}
