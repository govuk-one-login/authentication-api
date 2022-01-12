package uk.gov.di.authentication.shared.entity;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBHashKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBIndexHashKey;

import java.util.ArrayList;
import java.util.List;

public class ClientRegistry {

    private String clientID;
    private String clientName;
    private String publicKey;
    private List<String> postLogoutRedirectUrls = new ArrayList<>();
    private List<String> scopes = new ArrayList<>();
    private List<String> redirectUrls = new ArrayList<>();
    private List<String> contacts = new ArrayList<>();
    private String serviceType;
    private String sectorIdentifierUri;
    private String subjectType;
    private boolean cookieConsentShared = false;
    private boolean isInternalService = false;
    private boolean consentRequired = false;
    private boolean testClient = false;
    private List<String> testClientEmailAllowlist = new ArrayList<>();

    @DynamoDBHashKey(attributeName = "ClientID")
    public String getClientID() {
        return clientID;
    }

    public ClientRegistry setClientID(String clientID) {
        this.clientID = clientID;
        return this;
    }

    @DynamoDBIndexHashKey(
            globalSecondaryIndexName = "ClientNameIndex",
            attributeName = "ClientName")
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

    @DynamoDBAttribute(attributeName = "PostLogoutRedirectUrls")
    public List<String> getPostLogoutRedirectUrls() {
        return postLogoutRedirectUrls;
    }

    public ClientRegistry setPostLogoutRedirectUrls(List<String> postLogoutRedirectUrls) {
        this.postLogoutRedirectUrls = postLogoutRedirectUrls;
        return this;
    }

    @DynamoDBAttribute(attributeName = "ServiceType")
    public String getServiceType() {
        return serviceType;
    }

    public ClientRegistry setServiceType(String serviceType) {
        this.serviceType = serviceType;
        return this;
    }

    @DynamoDBAttribute(attributeName = "SectorIdentifierUri")
    public String getSectorIdentifierUri() {
        return sectorIdentifierUri;
    }

    public ClientRegistry setSectorIdentifierUri(String sectorIdentifierUri) {
        this.sectorIdentifierUri = sectorIdentifierUri;
        return this;
    }

    @DynamoDBAttribute(attributeName = "SubjectType")
    public String getSubjectType() {
        return subjectType;
    }

    public ClientRegistry setSubjectType(String subjectType) {
        this.subjectType = subjectType;
        return this;
    }

    @DynamoDBAttribute(attributeName = "CookieConsentShared")
    public boolean isCookieConsentShared() {
        return cookieConsentShared;
    }

    public ClientRegistry setCookieConsentShared(boolean cookieConsent) {
        this.cookieConsentShared = cookieConsent;
        return this;
    }

    @DynamoDBAttribute(attributeName = "IsInternalService")
    public boolean isInternalService() {
        return isInternalService;
    }

    public ClientRegistry setInternalService(boolean internalService) {
        isInternalService = internalService;
        return this;
    }

    @DynamoDBAttribute(attributeName = "TestClient")
    public boolean isTestClient() {
        return testClient;
    }

    public ClientRegistry setTestClient(boolean testClient) {
        this.testClient = testClient;
        return this;
    }

    @DynamoDBAttribute(attributeName = "TestClientEmailAllowlist")
    public List<String> getTestClientEmailAllowlist() {
        return testClientEmailAllowlist;
    }

    public ClientRegistry setTestClientEmailAllowlist(List<String> testClientEmailAllowlist) {
        this.testClientEmailAllowlist = testClientEmailAllowlist;
        return this;
    }

    @DynamoDBAttribute(attributeName = "ConsentRequired")
    public boolean isConsentRequired() {
        return consentRequired;
    }

    public void setConsentRequired(boolean consentRequired) {
        this.consentRequired = consentRequired;
    }
}
