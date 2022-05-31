package uk.gov.di.authentication.clientregistry.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

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

    @SerializedName("claims")
    @Expose
    private List<String> claims;

    @SerializedName("sector_identifier_uri")
    @Expose
    private String sectorIdentifierUri;

    @SerializedName("client_type")
    @Expose
    private String clientType;

    public ClientRegistrationResponse(
            String clientName,
            String clientId,
            List<String> redirectUris,
            List<String> contacts,
            List<String> scopes,
            List<String> postLogoutRedirectUris,
            String backChannelLogoutUri,
            String serviceType,
            String subjectType,
            List<String> claims,
            String sectorIdentifierUri,
            String clientType) {
        this.clientName = clientName;
        this.clientId = clientId;
        this.redirectUris = redirectUris;
        this.contacts = contacts;
        this.scopes = scopes;
        this.postLogoutRedirectUris = postLogoutRedirectUris;
        this.backChannelLogoutUri = backChannelLogoutUri;
        this.serviceType = serviceType;
        this.subjectType = subjectType;
        this.claims = claims;
        this.sectorIdentifierUri = sectorIdentifierUri;
        this.clientType = clientType;
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

    public List<String> getClaims() {
        return claims;
    }

    public String getSectorIdentifierUri() {
        return sectorIdentifierUri;
    }

    public String getClientType() {
        return clientType;
    }
}
