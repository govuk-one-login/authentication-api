package uk.gov.di.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class Client {

    @JsonProperty("client_name")
    private String clientName;

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("client_secret")
    private String clientSecret;

    @JsonProperty("response_types")
    private List<String> allowedResponseTypes;

    @JsonProperty("redirect_uris")
    private List<String> redirectUris;

    @JsonProperty("contacts")
    private List<String> contacts;

    public Client(@JsonProperty(required = true, value = "client_name") String clientName,
                  @JsonProperty(required = true, value = "client_id") String clientId,
                  @JsonProperty(required = true, value = "client_secret") String clientSecret,
                  @JsonProperty(required = true, value = "response_types") List<String> allowedResponseTypes,
                  @JsonProperty(required = true, value = "redirect_uris") List<String> redirectUris,
                  @JsonProperty(required = true, value = "contacts") List<String> contacts) {
        this.clientName = clientName;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.allowedResponseTypes = allowedResponseTypes;
        this.redirectUris = redirectUris;
        this.contacts = contacts;
    }

    public String getClientName() {
        return clientName;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public List<String> getAllowedResponseTypes() {
        return allowedResponseTypes;
    }

    public List<String> getRedirectUris() {
        return redirectUris;
    }

    public List<String> getContacts() {
        return contacts;
    }
}
