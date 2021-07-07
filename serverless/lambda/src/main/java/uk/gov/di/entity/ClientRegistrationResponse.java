package uk.gov.di.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class ClientRegistrationResponse {

    @JsonProperty("client_name")
    private String clientName;

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("redirect_uris")
    private List<String> redirectUris;

    @JsonProperty("contacts")
    private List<String> contacts;

    public ClientRegistrationResponse(
            @JsonProperty(required = true, value = "client_name") String clientName,
            @JsonProperty(required = true, value = "client_id") String clientId,
            @JsonProperty(required = true, value = "redirect_uris") List<String> redirectUris,
            @JsonProperty(required = true, value = "contacts") List<String> contacts) {
        this.clientName = clientName;
        this.clientId = clientId;
        this.redirectUris = redirectUris;
        this.contacts = contacts;
    }

    public String getClientName() {
        return clientName;
    }

    public String getClientId() {
        return clientId;
    }

    public List<String> getRedirectUris() {
        return redirectUris;
    }

    public List<String> getContacts() {
        return contacts;
    }
}
