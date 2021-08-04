package uk.gov.di.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

public class ClientInfoResponse {

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("client_name")
    private String clientName;

    @JsonProperty("scopes")
    private List<String> scopes = new ArrayList<>();

    public ClientInfoResponse(
            @JsonProperty(required = true, value = "client_id") String clientId,
            @JsonProperty(required = true, value = "client_name") String clientName,
            @JsonProperty(required = true, value = "scopes") List<String> scopes) {
        this.clientId = clientId;
        this.clientName = clientName;
        this.scopes = scopes;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientName() {
        return clientName;
    }

    public List<String> getScopes() {
        return scopes;
    }
}
