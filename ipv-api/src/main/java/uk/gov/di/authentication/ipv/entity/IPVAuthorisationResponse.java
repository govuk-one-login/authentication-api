package uk.gov.di.authentication.ipv.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import jakarta.validation.constraints.NotNull;

public class IPVAuthorisationResponse {

    @SerializedName("redirectUri")
    @Expose
    @NotNull
    private String redirectUri;

    public IPVAuthorisationResponse() {}

    public IPVAuthorisationResponse(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getRedirectUri() {
        return redirectUri;
    }
}
