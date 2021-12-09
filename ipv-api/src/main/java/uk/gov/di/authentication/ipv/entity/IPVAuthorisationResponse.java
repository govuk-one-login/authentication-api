package uk.gov.di.authentication.ipv.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.authentication.shared.entity.BaseAPIResponse;
import uk.gov.di.authentication.shared.entity.SessionState;

public class IPVAuthorisationResponse extends BaseAPIResponse {

    @JsonProperty("redirectUri")
    private String redirectUri;

    public IPVAuthorisationResponse(
            @JsonProperty(required = true, value = "sessionState") SessionState sessionState,
            @JsonProperty(required = true, value = "redirectUri") String redirectUri) {
        super(sessionState);
        this.redirectUri = redirectUri;
    }

    public String getRedirectUri() {
        return redirectUri;
    }
}
