package uk.gov.di.orchestration.shared.entity;

import com.google.gson.annotations.Expose;
import com.nimbusds.oauth2.sdk.id.Subject;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VectorOfTrust;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VotVocabVersion;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VtrSummary;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public class ClientSession {

    @Expose private Map<String, List<String>> authRequestParams;

    @Expose private String idTokenHint;

    @Expose private LocalDateTime creationDate;


    /**
     * @deprecated ClientSession is to use vtrList and no longer use effectiveVectorOfTrust. Must be
     *     retained until Authentication no longer depend on this field.
     */
    @Deprecated(forRemoval = true)
    @Expose
    private VectorOfTrust effectiveVectorOfTrust;

    @Expose private VtrSummary vtrSummary;

    @Expose private Subject docAppSubjectId;

    @Expose private String clientName;

    public ClientSession(
            Map<String, List<String>> authRequestParams,
            LocalDateTime creationDate,
            VtrSummary vtrSummary,
            VectorOfTrust effectiveVectorOfTrust,
            String clientName) {
        this.authRequestParams = authRequestParams;
        this.creationDate = creationDate;
        this.effectiveVectorOfTrust = effectiveVectorOfTrust;
        this.clientName = clientName;
    }

    public ClientSession(
            Map<String, List<String>> authRequestParams,
            LocalDateTime creationDate,
            VtrSummary vtrSummary,
            String clientName) {
        this.authRequestParams = authRequestParams;
        this.creationDate = creationDate;
        this.vtrSummary = vtrSummary;
        this.effectiveVectorOfTrust = VotVocabVersion.V1.normaliseVector(vtrSummary.effectiveVector());
        this.clientName = clientName;
    }

    public ClientSession setIdTokenHint(String idTokenHint) {
        this.idTokenHint = idTokenHint;
        return this;
    }

    public Map<String, List<String>> getAuthRequestParams() {
        return authRequestParams;
    }

    public String getIdTokenHint() {
        return idTokenHint;
    }

    public LocalDateTime getCreationDate() {
        return creationDate;
    }

    public Subject getDocAppSubjectId() {
        return docAppSubjectId;
    }

    public ClientSession setDocAppSubjectId(Subject docAppSubjectId) {
        this.docAppSubjectId = docAppSubjectId;
        return this;
    }

    public String getClientName() {
        return clientName;
    }

    public VtrSummary getVtrSummary() {
        return vtrSummary;
    }

    public String getVtrLocsAsCommaSeparatedString() {
        List<VectorOfTrustLegacy> orderedVtrList = VectorOfTrustLegacy.orderVtrList(this.vtrList);
        StringBuilder strBuilder = new StringBuilder();
        for (VectorOfTrustLegacy vtr : orderedVtrList) {
            String loc =
                    vtr.containsLevelOfConfidence()
                            ? vtr.getLevelOfConfidence().getValue()
                            : LevelOfConfidence.NONE.getValue();
            strBuilder.append(loc).append(",");
        }
        if (!strBuilder.isEmpty()) {
            strBuilder.setLength(strBuilder.length() - 1);
            return strBuilder.toString();
        }
        return "";
    }
}
