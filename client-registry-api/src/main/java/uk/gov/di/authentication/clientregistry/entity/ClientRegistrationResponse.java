package uk.gov.di.authentication.clientregistry.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.orchestration.shared.validation.Required;

import java.util.List;

public class ClientRegistrationResponse {

    @SerializedName("client_name")
    @Expose
    @Required
    private String clientName;

    @SerializedName("client_id")
    @Expose
    @Required
    private String clientId;

    @SerializedName("redirect_uris")
    @Expose
    @Required
    private List<String> redirectUris;

    @SerializedName("contacts")
    @Expose
    @Required
    private List<String> contacts;

    @SerializedName("public_key_source")
    @Expose
    @Required
    private String publicKeySource;

    @SerializedName("public_key")
    @Expose
    private String publicKey;

    @SerializedName("jwks_uri")
    @Expose
    private String jwksUrl;

    @SerializedName("scopes")
    @Expose
    @Required
    private List<String> scopes;

    @SerializedName("post_logout_redirect_uris")
    @Expose
    @Required
    private List<String> postLogoutRedirectUris;

    @SerializedName("back_channel_logout_uri")
    @Expose
    private String backChannelLogoutUri;

    @SerializedName("subject_type")
    @Expose
    @Required
    private String subjectType;

    @SerializedName("token_endpoint_auth_method")
    @Expose
    @Required
    private final String tokenAuthMethod = "private_key_jwt";

    @SerializedName("response_type")
    @Expose
    @Required
    private final String responseType = "code";

    @SerializedName("service_type")
    @Expose
    @Required
    private String serviceType;

    @SerializedName("jar_validation_required")
    @Expose
    @Required
    private boolean jarValidationRequired;

    @SerializedName("claims")
    @Expose
    private List<String> claims;

    @SerializedName("sector_identifier_uri")
    @Expose
    private String sectorIdentifierUri;

    @SerializedName("client_type")
    @Expose
    private String clientType;

    @SerializedName("id_token_signing_algorithm")
    @Expose
    private String idTokenSigningAlgorithm;

    @SerializedName("channel")
    @Expose
    @Required
    private String channel;

    @SerializedName("max_age_enabled")
    @Expose
    @Required
    private boolean maxAgeEnabled;

    @SerializedName("pkce_enforced")
    @Expose
    @Required
    private boolean pkceEnforced;

    @SerializedName("landing_page_url")
    @Expose
    private String landingPageUrl;

    public ClientRegistrationResponse(
            String clientName,
            String clientId,
            List<String> redirectUris,
            List<String> contacts,
            String publicKeySource,
            String publicKey,
            String jwksUrl,
            List<String> scopes,
            List<String> postLogoutRedirectUris,
            String backChannelLogoutUri,
            String serviceType,
            String subjectType,
            boolean jarValidationRequired,
            List<String> claims,
            String sectorIdentifierUri,
            String clientType,
            String idTokenSigningAlgorithm,
            String channel,
            boolean maxAgeEnabled,
            boolean pkceEnforced,
            String landingPageUrl) {
        this.clientName = clientName;
        this.clientId = clientId;
        this.redirectUris = redirectUris;
        this.contacts = contacts;
        this.publicKeySource = publicKeySource;
        this.publicKey = publicKey;
        this.jwksUrl = jwksUrl;
        this.scopes = scopes;
        this.postLogoutRedirectUris = postLogoutRedirectUris;
        this.backChannelLogoutUri = backChannelLogoutUri;
        this.serviceType = serviceType;
        this.subjectType = subjectType;
        this.jarValidationRequired = jarValidationRequired;
        this.claims = claims;
        this.sectorIdentifierUri = sectorIdentifierUri;
        this.clientType = clientType;
        this.idTokenSigningAlgorithm = idTokenSigningAlgorithm;
        this.channel = channel;
        this.maxAgeEnabled = maxAgeEnabled;
        this.pkceEnforced = pkceEnforced;
        this.landingPageUrl = landingPageUrl;
    }

    public ClientRegistrationResponse() {}

    public ClientRegistrationResponse setPostLogoutRedirectUris(
            List<String> postLogoutRedirectUris) {
        this.postLogoutRedirectUris = postLogoutRedirectUris;
        return this;
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

    public String getPublicKeySource() {
        return publicKeySource;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getJwksUrl() {
        return jwksUrl;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public List<String> getPostLogoutRedirectUris() {
        return postLogoutRedirectUris;
    }

    public String getBackChannelLogoutUri() {
        return backChannelLogoutUri;
    }

    public String getSubjectType() {
        return subjectType;
    }

    public String getTokenAuthMethod() {
        return tokenAuthMethod;
    }

    public String getResponseType() {
        return responseType;
    }

    public String getServiceType() {
        return serviceType;
    }

    public boolean getJarValidationRequired() {
        return jarValidationRequired;
    }

    public List<String> getClaims() {
        return claims;
    }

    public String getSectorIdentifierUri() {
        return sectorIdentifierUri;
    }

    public String getClientType() {
        return clientType;
    }

    public String getIdTokenSigningAlgorithm() {
        return idTokenSigningAlgorithm;
    }

    public boolean isMaxAgeEnabled() {
        return maxAgeEnabled;
    }

    public boolean isPKCEEnforced() {
        return pkceEnforced;
    }

    public String getLandingPageUrl() {
        return landingPageUrl;
    }
}
