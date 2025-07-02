package uk.gov.di.orchestration.shared.entity;

import com.nimbusds.jose.JWSAlgorithm;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSecondaryPartitionKey;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@DynamoDbBean
public class ClientRegistry {

    private String clientID;
    private String clientName;
    private String publicKeySource;
    private String publicKey;
    private String jwksUrl;
    private List<String> postLogoutRedirectUrls = new ArrayList<>();
    public String backChannelLogoutUri;
    private List<String> scopes = new ArrayList<>();
    private List<String> redirectUrls = new ArrayList<>();
    private List<String> contacts = new ArrayList<>();
    private String serviceType;
    private String sectorIdentifierUri;
    private String subjectType;
    private boolean isActive = true;
    private boolean cookieConsentShared = false;
    private boolean jarValidationRequired = false;
    private boolean testClient = false;
    private List<String> testClientEmailAllowlist = new ArrayList<>();
    private List<String> claims = new ArrayList<>();
    private String clientType;
    private boolean identityVerificationSupported = false;
    private String tokenAuthMethod;
    private String clientSecret;
    private String landingPageUrl;

    private boolean oneLoginService = false;
    private String idTokenSigningAlgorithm = "ES256";
    private boolean smokeTest = false;
    private List<String> clientLoCs = new ArrayList<>();
    private boolean permitMissingNonce = false;
    private String channel;
    private boolean maxAgeEnabled = false;
    private boolean pkceEnforced = false;
    private Integer rateLimit;

    private static final Set<String> RS256_MAPPINGS =
            Set.of(JWSAlgorithm.RS256.getName(), "RSA256");

    public ClientRegistry() {}

    @DynamoDbPartitionKey
    @DynamoDbAttribute("ClientID")
    public String getClientID() {
        return clientID;
    }

    public void setClientID(String clientID) {
        this.clientID = clientID;
    }

    public ClientRegistry withClientID(String clientID) {
        this.clientID = clientID;
        return this;
    }

    @DynamoDbSecondaryPartitionKey(indexNames = {"ClientNameIndex"})
    @DynamoDbAttribute("ClientName")
    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public ClientRegistry withClientName(String clientName) {
        this.clientName = clientName;
        return this;
    }

    @DynamoDbAttribute("PublicKeySource")
    public String getPublicKeySource() {
        return Optional.ofNullable(publicKeySource).orElseGet(PublicKeySource.STATIC::getValue);
    }

    public void setPublicKeySource(String publicKeySource) {
        this.publicKeySource = publicKeySource;
    }

    public ClientRegistry withPublicKeySource(String publicKeySource) {
        this.publicKeySource = publicKeySource;
        return this;
    }

    @DynamoDbAttribute("PublicKey")
    public String getPublicKey() {
        return PublicKeySource.JWKS.getValue().equals(publicKeySource) ? null : publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public ClientRegistry withPublicKey(String publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    @DynamoDbAttribute("JwksUrl")
    public String getJwksUrl() {
        return PublicKeySource.JWKS.getValue().equals(publicKeySource) ? jwksUrl : null;
    }

    public void setJwksUrl(String jwksUrl) {
        this.jwksUrl = jwksUrl;
    }

    public ClientRegistry withJwksUrl(String jwksUrl) {
        this.jwksUrl = jwksUrl;
        return this;
    }

    @DynamoDbAttribute("Scopes")
    public List<String> getScopes() {
        return scopes;
    }

    public void setScopes(List<String> scopes) {
        this.scopes = scopes;
    }

    public ClientRegistry withScopes(List<String> scopes) {
        this.scopes = scopes;
        return this;
    }

    @DynamoDbAttribute("RedirectUrls")
    public List<String> getRedirectUrls() {
        return redirectUrls;
    }

    public void setRedirectUrls(List<String> redirectUrls) {
        this.redirectUrls = redirectUrls;
    }

    public ClientRegistry withRedirectUrls(List<String> redirectUrls) {
        this.redirectUrls = redirectUrls;
        return this;
    }

    @DynamoDbAttribute("Contacts")
    public List<String> getContacts() {
        return contacts;
    }

    public void setContacts(List<String> contacts) {
        this.contacts = contacts;
    }

    public ClientRegistry withContacts(List<String> contacts) {
        this.contacts = contacts;
        return this;
    }

    @DynamoDbAttribute("PostLogoutRedirectUrls")
    public List<String> getPostLogoutRedirectUrls() {
        return postLogoutRedirectUrls;
    }

    public void setPostLogoutRedirectUrls(List<String> postLogoutRedirectUrls) {
        this.postLogoutRedirectUrls = postLogoutRedirectUrls;
    }

    public ClientRegistry withPostLogoutRedirectUrls(List<String> postLogoutRedirectUrls) {
        this.postLogoutRedirectUrls = postLogoutRedirectUrls;
        return this;
    }

    @DynamoDbAttribute("BackChannelLogoutUri")
    public String getBackChannelLogoutUri() {
        return backChannelLogoutUri;
    }

    public void setBackChannelLogoutUri(String backChannelLogoutUri) {
        this.backChannelLogoutUri = backChannelLogoutUri;
    }

    public ClientRegistry withBackChannelLogoutUri(String backChannelLogoutUri) {
        this.backChannelLogoutUri = backChannelLogoutUri;
        return this;
    }

    @DynamoDbAttribute("ServiceType")
    public String getServiceType() {
        return serviceType;
    }

    public void setServiceType(String serviceType) {
        this.serviceType = serviceType;
    }

    public ClientRegistry withServiceType(String serviceType) {
        this.serviceType = serviceType;
        return this;
    }

    @DynamoDbAttribute("SectorIdentifierUri")
    public String getSectorIdentifierUri() {
        return sectorIdentifierUri;
    }

    public void setSectorIdentifierUri(String sectorIdentifierUri) {
        this.sectorIdentifierUri = sectorIdentifierUri;
    }

    public ClientRegistry withSectorIdentifierUri(String sectorIdentifierUri) {
        this.sectorIdentifierUri = sectorIdentifierUri;
        return this;
    }

    @DynamoDbAttribute("SubjectType")
    public String getSubjectType() {
        return subjectType;
    }

    public void setSubjectType(String subjectType) {
        this.subjectType = subjectType;
    }

    public ClientRegistry withSubjectType(String subjectType) {
        this.subjectType = subjectType;
        return this;
    }

    @DynamoDbAttribute("IsActive")
    public boolean isActive() {
        return isActive;
    }

    public void setActive(boolean isActive) {
        this.isActive = isActive;
    }

    public ClientRegistry withActive(boolean isActive) {
        this.isActive = isActive;
        return this;
    }

    @DynamoDbAttribute("CookieConsentShared")
    public boolean isCookieConsentShared() {
        return cookieConsentShared;
    }

    public void setCookieConsentShared(boolean cookieConsentShared) {
        this.cookieConsentShared = cookieConsentShared;
    }

    public ClientRegistry withCookieConsentShared(boolean cookieConsent) {
        this.cookieConsentShared = cookieConsent;
        return this;
    }

    @DynamoDbAttribute("TestClient")
    public boolean isTestClient() {
        return testClient;
    }

    public void setTestClient(boolean testClient) {
        this.testClient = testClient;
    }

    public ClientRegistry withTestClient(boolean testClient) {
        this.testClient = testClient;
        return this;
    }

    @DynamoDbAttribute("TestClientEmailAllowlist")
    public List<String> getTestClientEmailAllowlist() {
        return testClientEmailAllowlist;
    }

    public void setTestClientEmailAllowlist(List<String> testClientEmailAllowlist) {
        this.testClientEmailAllowlist = testClientEmailAllowlist;
    }

    public ClientRegistry withTestClientEmailAllowlist(List<String> testClientEmailAllowlist) {
        this.testClientEmailAllowlist = testClientEmailAllowlist;
        return this;
    }

    @DynamoDbAttribute("JarValidationRequired")
    public boolean isJarValidationRequired() {
        return jarValidationRequired;
    }

    public void setJarValidationRequired(boolean jarValidationRequired) {
        this.jarValidationRequired = jarValidationRequired;
    }

    public ClientRegistry withJarValidationRequired(boolean jarValidationRequired) {
        this.jarValidationRequired = jarValidationRequired;
        return this;
    }

    @DynamoDbAttribute("Claims")
    public List<String> getClaims() {
        return claims;
    }

    public void setClaims(List<String> claims) {
        this.claims = claims;
    }

    public ClientRegistry withClaims(List<String> claims) {
        this.claims = claims;
        return this;
    }

    @DynamoDbAttribute("ClientType")
    public String getClientType() {
        return clientType;
    }

    public void setClientType(String clientType) {
        this.clientType = clientType;
    }

    public ClientRegistry withClientType(String clientType) {
        this.clientType = clientType;
        return this;
    }

    @DynamoDbAttribute("IdentityVerificationSupported")
    public boolean isIdentityVerificationSupported() {
        return identityVerificationSupported;
    }

    public void setIdentityVerificationSupported(boolean identityVerificationSupported) {
        this.identityVerificationSupported = identityVerificationSupported;
    }

    public ClientRegistry withIdentityVerificationSupported(boolean identityVerificationSupported) {
        this.identityVerificationSupported = identityVerificationSupported;
        return this;
    }

    @DynamoDbAttribute("OneLoginService")
    public boolean isOneLoginService() {
        return oneLoginService;
    }

    public void setOneLoginService(boolean oneLoginService) {
        this.oneLoginService = oneLoginService;
    }

    public ClientRegistry withOneLoginService(boolean oneLoginService) {
        this.oneLoginService = oneLoginService;
        return this;
    }

    @DynamoDbAttribute("IdTokenSigningAlgorithm")
    public String getIdTokenSigningAlgorithm() {
        return idTokenSigningAlgorithm != null && RS256_MAPPINGS.contains(idTokenSigningAlgorithm)
                ? JWSAlgorithm.RS256.getName()
                : idTokenSigningAlgorithm;
    }

    public void setIdTokenSigningAlgorithm(String algorithm) {
        this.idTokenSigningAlgorithm = algorithm;
    }

    public ClientRegistry withIdTokenSigningAlgorithm(String algorithm) {
        this.idTokenSigningAlgorithm = algorithm;
        return this;
    }

    @DynamoDbAttribute("TokenAuthMethod")
    public String getTokenAuthMethod() {
        return tokenAuthMethod;
    }

    public void setTokenAuthMethod(String tokenAuthMethod) {
        this.tokenAuthMethod = tokenAuthMethod;
    }

    public ClientRegistry withTokenAuthMethod(String tokenAuthMethod) {
        this.tokenAuthMethod = tokenAuthMethod;
        return this;
    }

    @DynamoDbAttribute("ClientSecret")
    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public ClientRegistry withClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
        return this;
    }

    @DynamoDbAttribute("SmokeTest")
    public boolean isSmokeTest() {
        return smokeTest;
    }

    public void setSmokeTest(boolean smokeTest) {
        this.smokeTest = smokeTest;
    }

    public ClientRegistry withSmokeTest(boolean smokeTest) {
        this.smokeTest = smokeTest;
        return this;
    }

    @DynamoDbAttribute("LandingPageUrl")
    public String getLandingPageUrl() {
        return landingPageUrl;
    }

    public void setLandingPageUrl(String landingPageUrl) {
        this.landingPageUrl = landingPageUrl;
    }

    public ClientRegistry withLandingPageUrl(String landingPageUrl) {
        this.landingPageUrl = landingPageUrl;
        return this;
    }

    @DynamoDbAttribute("ClientLoCs")
    public List<String> getClientLoCs() {
        if (clientLoCs.isEmpty()) {
            return identityVerificationSupported
                    ? List.of(
                            LevelOfConfidence.MEDIUM_LEVEL.getValue(),
                            LevelOfConfidence.NONE.getValue())
                    : List.of(LevelOfConfidence.NONE.getValue());
        }
        return clientLoCs;
    }

    public void setClientLoCs(List<String> clientLoCs) {
        this.clientLoCs = clientLoCs;
    }

    public ClientRegistry withClientLoCs(List<String> clientLoCs) {
        this.clientLoCs = clientLoCs;
        return this;
    }

    @DynamoDbAttribute("PermitMissingNonce")
    public boolean getPermitMissingNonce() {
        return permitMissingNonce;
    }

    public void setPermitMissingNonce(boolean permitMissingNonce) {
        this.permitMissingNonce = permitMissingNonce;
    }

    public boolean permitMissingNonce() {
        return !identityVerificationSupported && getPermitMissingNonce();
    }

    public ClientRegistry withPermitMissingNonce(boolean permitMissingNonce) {
        this.permitMissingNonce = permitMissingNonce;
        return this;
    }

    @DynamoDbAttribute("Channel")
    public String getChannel() {
        return Optional.ofNullable(channel).orElseGet(Channel.WEB::getValue);
    }

    public void setChannel(String channel) {
        this.channel = channel;
    }

    public ClientRegistry withChannel(String channel) {
        this.channel = channel;
        return this;
    }

    @DynamoDbAttribute("MaxAgeEnabled")
    public boolean getMaxAgeEnabled() {
        return maxAgeEnabled;
    }

    public void setMaxAgeEnabled(boolean maxAgeEnabled) {
        this.maxAgeEnabled = maxAgeEnabled;
    }

    public ClientRegistry withMaxAgeEnabled(boolean maxAgeEnabled) {
        this.maxAgeEnabled = maxAgeEnabled;
        return this;
    }

    @DynamoDbAttribute("PKCEEnforced")
    public boolean getPKCEEnforced() {
        return pkceEnforced;
    }

    public void setPKCEEnforced(boolean pkceEnforced) {
        this.pkceEnforced = pkceEnforced;
    }

    public ClientRegistry withPKCEEnforced(boolean pkceEnforced) {
        this.pkceEnforced = pkceEnforced;
        return this;
    }

    @DynamoDbAttribute("RateLimit")
    public Integer getRateLimit() {
        return rateLimit;
    }

    public void setRateLimit(Integer rateLimit) {
        this.rateLimit = rateLimit;
    }

    public ClientRegistry withRateLimit(Integer rateLimit) {
        this.rateLimit = rateLimit;
        return this;
    }
}
