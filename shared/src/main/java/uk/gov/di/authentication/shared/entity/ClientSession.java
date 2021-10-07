package uk.gov.di.authentication.shared.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public class ClientSession {

    @JsonProperty("auth_request_params")
    private Map<String, List<String>> authRequestParams;

    @JsonProperty("id_token_hint")
    private String idTokenHint;

    @JsonProperty("creation_date")
    private LocalDateTime creationDate;

    @JsonProperty("effective_vector_of_trust")
    private VectorOfTrust effectiveVectorOfTrust;

    public ClientSession(
            @JsonProperty(required = true, value = "auth_request_params")
                    Map<String, List<String>> authRequestParams,
            @JsonProperty(required = true, value = "creation_date") LocalDateTime creationDate,
            @JsonProperty(required = true, value = "effective_vector_of_trust")
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
}
