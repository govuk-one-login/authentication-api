package uk.gov.di.orchestration.shared.entity;

import com.google.gson.annotations.Expose;
import com.nimbusds.oauth2.sdk.id.Subject;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VectorOfTrust;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.VtrList;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class ClientSession {

    @Deprecated(forRemoval = true)
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

    @Expose private VtrList vtrList;

    // ATO-98: This should only ever be null if a session was in progress during release.
    @Expose private Boolean mfaRequired;

    // ATO-98: This should only ever be null if a session was in progress during release.
    @Expose private Boolean identityRequired;

    @Expose private Subject docAppSubjectId;

    @Expose private String clientName;

    public ClientSession(
            Map<String, List<String>> authRequestParams,
            LocalDateTime creationDate,
            VtrList vtrList,
            String clientName) {
        this.authRequestParams = authRequestParams;
        this.creationDate = creationDate;
        this.vtrList = vtrList;
        this.mfaRequired = vtrList.mfaRequired();
        this.identityRequired = vtrList.identityRequired();
        this.effectiveVectorOfTrust = vtrList.getEffectiveVectorOfTrust();
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

    public VtrList getVtrList() {
        return vtrList;
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
        return vtrList.getSelectedLevelOfConfidences().stream()
                .map(LevelOfConfidence::toString)
                .collect(Collectors.joining(","));
    }
}
