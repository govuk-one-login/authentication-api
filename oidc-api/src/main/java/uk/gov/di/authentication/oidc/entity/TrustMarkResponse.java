package uk.gov.di.authentication.oidc.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;

import java.util.List;

public class TrustMarkResponse {
    @JsonProperty("idp")
    private String idp;

    @JsonProperty("trustmark_provider")
    private String trustMark;

    @JsonProperty("C")
    private List<CredentialTrustLevel> c;

    public TrustMarkResponse(
            @JsonProperty(required = true, value = "idp") String idp,
            @JsonProperty(required = true, value = "trustmark_provider") String trustMark,
            @JsonProperty(required = true, value = "C") List<CredentialTrustLevel> c) {
        this.idp = idp;
        this.trustMark = trustMark;
        this.c = c;
    }

    public String getIdp() {
        return idp;
    }

    public String getTrustMark() {
        return trustMark;
    }

    public List<CredentialTrustLevel> getC() {
        return c;
    }
}
