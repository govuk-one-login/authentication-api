package uk.gov.di.authentication.shared.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.JsonAdapter;
import com.nimbusds.oauth2.sdk.id.Subject;
import uk.gov.di.authentication.shared.serialization.LocalDateTimeAdapter;
import uk.gov.di.authentication.shared.serialization.SubjectAdapter;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public class ClientSession {

    @Expose private Map<String, List<String>> authRequestParams;

    @Expose private String idTokenHint;

    @Expose
    @JsonAdapter(LocalDateTimeAdapter.class)
    private LocalDateTime creationDate;

    @Expose private VectorOfTrust effectiveVectorOfTrust;

    @JsonAdapter(SubjectAdapter.class)
    @Expose
    private Subject docAppSubjectId;

    public ClientSession(
            Map<String, List<String>> authRequestParams,
            LocalDateTime creationDate,
            VectorOfTrust effectiveVectorOfTrust) {
        this.authRequestParams = authRequestParams;
        this.creationDate = creationDate;
        this.effectiveVectorOfTrust = effectiveVectorOfTrust;
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

    public VectorOfTrust getEffectiveVectorOfTrust() {
        return effectiveVectorOfTrust;
    }

    public ClientSession setEffectiveVectorOfTrust(VectorOfTrust effectiveVectorOfTrust) {
        this.effectiveVectorOfTrust = effectiveVectorOfTrust;
        return this;
    }

    public Subject getDocAppSubjectId() {
        return docAppSubjectId;
    }

    public ClientSession setDocAppSubjectId(Subject docAppSubjectId) {
        this.docAppSubjectId = docAppSubjectId;
        return this;
    }
}
