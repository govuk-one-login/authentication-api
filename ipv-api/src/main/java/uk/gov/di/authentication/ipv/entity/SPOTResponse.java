package uk.gov.di.authentication.ipv.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

public class SPOTResponse {

    @JsonProperty private Map<String, Object> claims;

    @JsonProperty private String sub;

    @JsonProperty private String status;

    public SPOTResponse(
            @JsonProperty(value = "claim") Map<String, Object> claims,
            @JsonProperty(required = true, value = "sub") String sub,
            @JsonProperty(required = true, value = "status") String status) {
        this.claims = claims;
        this.sub = sub;
        this.status = status;
    }

    public Map<String, Object> getClaims() {
        return claims;
    }

    public String getSub() {
        return sub;
    }

    public String getStatus() {
        return status;
    }
}
