package uk.gov.di.authentication.oidc.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public class IdentityResponse {

    @Expose @Required private String sub;

    @Expose
    @Required
    @SerializedName("identityCredential")
    private String identityCredential;

    public IdentityResponse() {}
    ;

    public IdentityResponse(String sub, String identityCredential) {
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
