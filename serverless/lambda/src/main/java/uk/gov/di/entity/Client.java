package uk.gov.di.entity;

import java.util.List;


public class Client {

    private String clientName;
    private String clientId;
    private String clientSecret;
    private List<String> scopes;
    private List<String> allowedResponseTypes;
    private List<String> redirectUrls;
    private List<String> contacts;

    public Client(String clientName, String clientId, String clientSecret, List<String> scopes, List<String> allowedResponseTypes, List<String> redirectUrls, List<String> contacts) {
        this.clientName = clientName;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.scopes = scopes;
        this.allowedResponseTypes = allowedResponseTypes;
        this.redirectUrls = redirectUrls;
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

    public List<String> getScopes() {
        return scopes;
    }

    public List<String> getAllowedResponseTypes() {
        return allowedResponseTypes;
    }

    public List<String> getRedirectUrls() {
        return redirectUrls;
    }

    public List<String> getContacts() {
        return contacts;
    }
}
