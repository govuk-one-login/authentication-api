package uk.gov.di.entity;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class ClientRegistrationRequest {

    private String clientName;
    private List<String> redirectUris;
    private List<String> contacts;

    @JsonCreator
    public ClientRegistrationRequest(
            @JsonProperty(required = true, value = "client_name") String clientName,
            @JsonProperty(required = true, value = "redirect_uris")List<String> redirectUris,
            @JsonProperty(required = true, value = "contacts") List<String> contacts) {
        this.clientName = clientName;
        this.redirectUris = redirectUris;
        this.contacts = contacts;
    }

    public String getClientName() {
        return clientName;
    }

    public List<String> getRedirectUris() {
        return redirectUris;
    }

    public List<String> getContacts() {
        return contacts;
    }
}
