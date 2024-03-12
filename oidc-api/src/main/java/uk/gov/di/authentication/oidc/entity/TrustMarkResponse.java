package uk.gov.di.authentication.oidc.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevelCode;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidenceCode;
import uk.gov.di.orchestration.shared.validation.Required;

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
    private List<CredentialTrustLevelCode> c;

    @SerializedName("P")
    @Expose
    @Required
    private List<LevelOfConfidenceCode> p;

    public TrustMarkResponse() {}

    public TrustMarkResponse(
            String idp,
            String trustMark,
            List<CredentialTrustLevelCode> c,
            List<LevelOfConfidenceCode> p) {
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

    public List<CredentialTrustLevelCode> getC() {
        return c;
    }

    public List<LevelOfConfidenceCode> getP() {
        return p;
    }
}
