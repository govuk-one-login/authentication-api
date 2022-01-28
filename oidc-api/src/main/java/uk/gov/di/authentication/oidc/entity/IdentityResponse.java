package uk.gov.di.authentication.oidc.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class IdentityResponse {

    @JsonProperty("sub")
    private String sub;

    @JsonProperty("identityCredential")
    private String identityCredential;

    public IdentityResponse(
            @JsonProperty(required = true, value = "sub") String sub,
            @JsonProperty(required = true, value = "identityCredential")
                    String identityCredential) {
        this.sub = sub;
        this.identityCredential = identityCredential;
    }

    public String getSub() {
        return sub;
    }

    public String getIdentityCredential() {
        return identityCredential;
    }
}
