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

    public String getClientName() {
        return clientName;
    }
}
