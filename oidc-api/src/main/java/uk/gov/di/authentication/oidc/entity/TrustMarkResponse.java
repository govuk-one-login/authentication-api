package uk.gov.di.authentication.oidc.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import jakarta.validation.constraints.NotNull;

import java.util.List;

public class TrustMarkResponse {
    @JsonProperty("idp")
    @Expose
    @NotNull
    private String idp;

    @SerializedName("trustmark_provider")
    @Expose
    @NotNull
    private String trustMark;

    @SerializedName("C")
    @Expose
    @NotNull
    private List<String> c;

    @SerializedName("P")
    @Expose
    @NotNull
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
