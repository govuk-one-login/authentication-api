package uk.gov.di.entity;

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

    @JsonProperty("email")
    private String email;

    public ClientSession(
            @JsonProperty(required = true, value = "auth_request_params")
                    Map<String, List<String>> authRequestParams,
            @JsonProperty(required = true, value = "creation_date") LocalDateTime creationDate,
            @JsonProperty(required = true, value = "email") String email) {
        this.authRequestParams = authRequestParams;
        this.creationDate = creationDate;
        this.email = email;
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

    public String getEmail() {
        return email;
    }

    public LocalDateTime getCreationDate() {
        return creationDate;
    }
}
