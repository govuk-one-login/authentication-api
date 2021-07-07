package uk.gov.di.entity;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBHashKey;

import java.util.List;

public class ClientRegistry {

    private String clientID;
    private String clientName;
    private String publicKey;
    private List<String> scopes;
    private List<String> redirectUrls;
    private List<String> contacts;

    @DynamoDBHashKey(attributeName = "ClientID")
    public String getClientID() {
        return clientID;
    }

    public ClientRegistry setClientID(String clientID) {
        this.clientID = clientID;
        return this;
    }

    @DynamoDBAttribute(attributeName = "ClientName")
    public String getClientName() {
        return clientName;
    }

    public ClientRegistry setClientName(String clientName) {
        this.clientName = clientName;
        return this;
    }

    @DynamoDBAttribute(attributeName = "PublicKey")
    public String getPublicKey() {
        return publicKey;
    }

    public ClientRegistry setPublicKey(String publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    @DynamoDBAttribute(attributeName = "Scopes")
    public List<String> getScopes() {
        return scopes;
    }

    public ClientRegistry setScopes(List<String> scopes) {
        this.scopes = scopes;
        return this;
    }

    @DynamoDBAttribute(attributeName = "RedirectUrls")
    public List<String> getRedirectUrls() {
        return redirectUrls;
    }

    public ClientRegistry setRedirectUrls(List<String> redirectUrls) {
        this.redirectUrls = redirectUrls;
        return this;
    }

    @DynamoDBAttribute(attributeName = "Contacts")
    public List<String> getContacts() {
        return contacts;
    }

    public ClientRegistry setContacts(List<String> contacts) {
        this.contacts = contacts;
        return this;
    }
}
