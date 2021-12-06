package uk.gov.di.authentication.oidc.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class TrustMarkResponse {
    @JsonProperty("idp")
    private String idp;

    @JsonProperty("trustmark_provider")
    private String trustMark;

    @JsonProperty("C")
    private List<String> c;

    @JsonProperty("P")
    private List<String> p;

    public TrustMarkResponse(
            @JsonProperty(required = true, value = "idp") String idp,
            @JsonProperty(required = true, value = "trustmark_provider") String trustMark,
            @JsonProperty(required = true, value = "C") List<String> c,
            @JsonProperty(required = true, value = "P") List<String> p) {
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
