package uk.gov.di.orchestration.shared.entity;

import com.google.gson.annotations.Expose;
import com.nimbusds.oauth2.sdk.id.Subject;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

public class ClientSession {

    @Expose private Map<String, List<String>> authRequestParams;

    @Expose private String idTokenHint;

    @Expose private LocalDateTime creationDate;

    @Expose private VectorOfTrust effectiveVectorOfTrust;

    @Expose private List<VectorOfTrust> vtrList = new ArrayList<>();

    @Expose private Subject docAppSubjectId;

    @Expose private String clientName;

    public ClientSession(
            Map<String, List<String>> authRequestParams,
            LocalDateTime creationDate,
            VectorOfTrust effectiveVectorOfTrust,
            String clientName) {
        this.authRequestParams = authRequestParams;
        this.creationDate = creationDate;
        this.effectiveVectorOfTrust = effectiveVectorOfTrust;
        this.vtrList.add(effectiveVectorOfTrust);
        this.clientName = clientName;
    }

    public ClientSession(
            Map<String, List<String>> authRequestParams,
            LocalDateTime creationDate,
            List<VectorOfTrust> vtrList,
            String clientName) {
        this.authRequestParams = authRequestParams;
        this.creationDate = creationDate;
        this.vtrList = vtrList;
        this.effectiveVectorOfTrust = getVtrWithLowestCredentialTrustLevel();
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

    public List<VectorOfTrust> getVtrList() {
        return vtrList;
    }

    public ClientSession setEffectiveVectorOfTrust(VectorOfTrust effectiveVectorOfTrust) {
        this.effectiveVectorOfTrust = effectiveVectorOfTrust;
        this.vtrList.add(effectiveVectorOfTrust);
        return this;
    }

    public VectorOfTrust getVtrWithLowestCredentialTrustLevel() {
        return this.vtrList.stream()
                .filter(vot -> vot.getLevelOfConfidence() != null)
                .min(
                        Comparator.comparing(
                                        VectorOfTrust::getLevelOfConfidence,
                                        Comparator.nullsFirst(Comparator.naturalOrder()))
                                .thenComparing(
                                        VectorOfTrust::getCredentialTrustLevel,
                                        Comparator.nullsFirst(Comparator.naturalOrder())))
                .orElseGet(
                        () ->
                                this.vtrList.stream()
                                        .min(
                                                Comparator.comparing(
                                                        VectorOfTrust::getCredentialTrustLevel,
                                                        Comparator.nullsFirst(
                                                                Comparator.naturalOrder())))
                                        .orElseThrow(
                                                () ->
                                                        new IllegalArgumentException(
                                                                "Invalid VTR attribute")));
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

    public String getVtrLocsAsCommaSeparatedString() {
        StringBuilder strBuilder = new StringBuilder();
        for (VectorOfTrust vtr : this.vtrList) {
            String loc =
                    vtr.containsLevelOfConfidence()
                            ? vtr.getLevelOfConfidence().getValue()
                            : LevelOfConfidence.NONE.getValue();
            strBuilder.append(loc).append(",");
        }
        if (strBuilder.length() > 0) {
            strBuilder.setLength(strBuilder.length() - 1);
            return strBuilder.toString();
        }
        return "";
    }
}
