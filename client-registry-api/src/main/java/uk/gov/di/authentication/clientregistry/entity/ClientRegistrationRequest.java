package uk.gov.di.authentication.clientregistry.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

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
    private List<String> postLogoutRedirectUris = new ArrayList<>();

    @JsonProperty("service_type")
    private String serviceType;

    @JsonProperty("sector_identifier_uri")
    private String sectorIdentifierUri;

    @JsonProperty("subject_type")
    private String subjectType;

    @JsonProperty("vectors_of_trust")
    private String vectorsOfTrust;

    public ClientRegistrationRequest(
            @JsonProperty(required = true, value = "client_name") String clientName,
            @JsonProperty(required = true, value = "redirect_uris") List<String> redirectUris,
            @JsonProperty(required = true, value = "contacts") List<String> contacts,
            @JsonProperty(required = true, value = "public_key") String publicKey,
            @JsonProperty(required = true, value = "scopes") List<String> scopes,
            @JsonProperty(value = "post_logout_redirect_uris") List<String> postLogoutRedirectUris,
            @JsonProperty(required = true, value = "service_type") String serviceType,
            @JsonProperty(required = true, value = "sector_identifier_uri")
                    String sectorIdentifierUri,
            @JsonProperty(required = true, value = "subject_type") String subjectType,
            @JsonProperty(required = false, value = "vectors_of_trust") String vectorsOfTrust) {
        this.clientName = clientName;
        this.redirectUris = redirectUris;
        this.contacts = contacts;
        this.publicKey = publicKey;
        this.scopes = scopes;
        if (Objects.nonNull(postLogoutRedirectUris)) {
            this.postLogoutRedirectUris = postLogoutRedirectUris;
        }
        this.serviceType = serviceType;
        this.sectorIdentifierUri = sectorIdentifierUri;
        this.subjectType = subjectType;
        this.vectorsOfTrust = vectorsOfTrust;
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

    public String getServiceType() {
        return serviceType;
    }

    public String getSectorIdentifierUri() {
        return sectorIdentifierUri;
    }

    public String getSubjectType() {
        return subjectType;
    }

    public String getVectorsOfTrust() {
        return vectorsOfTrust;
    }

    public void setVectorsOfTrust(String vectorsOfTrust) {
        this.vectorsOfTrust = vectorsOfTrust;
    }
}
