package uk.gov.di.authentication.oidc.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

import java.util.List;

public class TrustMarkResponse {
    @Expose @Required private String idp;

    @SerializedName("trustmark_provider")
    @Expose
    @Required
    private String trustMark;

    @SerializedName("C")
    @Expose
    @Required
    private List<String> c;

    @SerializedName("P")
    @Expose
    @Required
    private List<String> p;

    public TrustMarkResponse() {}

    public TrustMarkResponse(String idp, String trustMark, List<String> c, List<String> p) {
        this.idp = idp;
        this.trustMark = trustMark;
        this.c = c;
        this.p = p;
    }

    public String getIdp() {
        return idp;
    }

    public String getTrustMark() {
        return trustMark;
    }

    public List<String> getC() {
        return c;
    }

    public List<String> getP() {
        return p;
    }
}
