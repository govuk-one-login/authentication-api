package uk.gov.di.authentication.shared.entity;

import com.google.gson.annotations.Expose;
import com.nimbusds.oauth2.sdk.id.Subject;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public class ClientSession {

    @Expose private Map<String, List<String>> authRequestParams;

    @Expose private LocalDateTime creationDate;

    @Expose private VectorOfTrust effectiveVectorOfTrust;

    @Expose private boolean identityRequired;

    @Expose private boolean mfaRequired;

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
        this.identityRequired =
                effectiveVectorOfTrust != null
                        && effectiveVectorOfTrust.getLevelOfConfidence() != null
                        && effectiveVectorOfTrust.getLevelOfConfidence() != LevelOfConfidence.NONE;
        this.mfaRequired =
                effectiveVectorOfTrust != null
                        && effectiveVectorOfTrust.getCredentialTrustLevel()
                                == CredentialTrustLevel.MEDIUM_LEVEL;
        this.clientName = clientName;
    }

    public Map<String, List<String>> getAuthRequestParams() {
        return authRequestParams;
    }

    public LocalDateTime getCreationDate() {
        return creationDate;
    }

    public VectorOfTrust getEffectiveVectorOfTrust() {
        return effectiveVectorOfTrust;
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

    public boolean getIdentityRequired() {
        return identityRequired;
    }

    public boolean getMfaRequired() {
        return mfaRequired;
    }
}
