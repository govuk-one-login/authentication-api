package uk.gov.di.authentication.ipv.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

import java.util.Map;

public class SPOTResponse {

    @Expose
    @SerializedName("claims")
    private Map<String, Object> claims;

    @Expose @Required private String sub;

    @Expose @Required private SPOTStatus status;

    public SPOTResponse() {}

    public SPOTResponse(Map<String, Object> claims, String sub, SPOTStatus status) {
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

    public SPOTStatus getStatus() {
        return status;
    }
}
