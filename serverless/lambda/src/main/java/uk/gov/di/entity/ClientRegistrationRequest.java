package uk.gov.di.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class ClientRegistrationRequest {

    @JsonProperty("client_name")
    private String clientName;

    @JsonProperty("redirect_uris")
    private List<String> redirectUris;

    @JsonProperty("contacts")
    private List<String> contacts;

    @JsonProperty("public_key")
    private String publicKey;

    @JsonProperty("scopes")
    private List<String> scopes;

    @JsonProperty("post_logout_redirect_uris")
    private List<String> postLogoutRedirectUris;

    public ClientRegistrationRequest(
            @JsonProperty(required = true, value = "client_name") String clientName,
            @JsonProperty(required = true, value = "redirect_uris") List<String> redirectUris,
            @JsonProperty(required = true, value = "contacts") List<String> contacts,
            @JsonProperty(required = true, value = "public_key") String publicKey,
            @JsonProperty(required = true, value = "scopes") List<String> scopes,
            @JsonProperty(value = "post_logout_redirect_uris")
                    List<String> postLogoutRedirectUris) {
        this.clientName = clientName;
        this.redirectUris = redirectUris;
        this.contacts = contacts;
        this.publicKey = publicKey;
        this.scopes = scopes;
        this.postLogoutRedirectUris = postLogoutRedirectUris;
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

    public String getPublicKey() {
        return publicKey;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public List<String> getPostLogoutRedirectUris() {
        return postLogoutRedirectUris;
    }
}
