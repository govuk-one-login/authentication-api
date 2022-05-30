package uk.gov.di.authentication.clientregistry.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.validation.Required;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class ClientRegistrationRequest {

    @SerializedName("client_name")
    @Expose
    @Required
    private String clientName;

    @SerializedName("redirect_uris")
    @Expose
    @Required
    private List<String> redirectUris;

    @SerializedName("contacts")
    @Expose
    @Required
    private List<String> contacts;

    @SerializedName("public_key")
    @Expose
    @Required
    private String publicKey;

    @SerializedName("scopes")
    @Expose
    @Required
    private List<String> scopes;

    @SerializedName("post_logout_redirect_uris")
    @Expose
    private List<String> postLogoutRedirectUris = new ArrayList<>();

    @SerializedName("back_channel_logout_uri")
    @Expose
    private String backChannelLogoutUri;

    @SerializedName("service_type")
    @Expose
    private String serviceType = String.valueOf(ServiceType.MANDATORY);

    @SerializedName("sector_identifier_uri")
    @Expose
    @Required
    private String sectorIdentifierUri;

    @SerializedName("subject_type")
    @Expose
    @Required
    private String subjectType;

    @SerializedName("identity_verification_required")
    @Expose
    private boolean identityVerificationRequired;

    @SerializedName("claims")
    @Expose
    private List<String> claims = new ArrayList<>();

    @SerializedName("client_type")
    @Expose
    private String clientType = ClientType.WEB.getValue();

    public ClientRegistrationRequest() {}

    public ClientRegistrationRequest(
            String clientName,
            List<String> redirectUris,
            List<String> contacts,
            String publicKey,
            List<String> scopes,
            List<String> postLogoutRedirectUris,
            String backChannelLogoutUri,
            String serviceType,
            String sectorIdentifierUri,
            String subjectType,
            boolean identityVerificationRequired,
            List<String> claims,
            String clientType) {
        this.clientName = clientName;
        this.redirectUris = redirectUris;
        this.contacts = contacts;
        this.publicKey = publicKey;
        this.scopes = scopes;
        if (Objects.nonNull(postLogoutRedirectUris)) {
            this.postLogoutRedirectUris = postLogoutRedirectUris;
        }
        this.backChannelLogoutUri = backChannelLogoutUri;
        if (Objects.isNull(serviceType)) {
            serviceType = String.valueOf(ServiceType.MANDATORY);
        }
        this.serviceType = serviceType;
        this.sectorIdentifierUri = sectorIdentifierUri;
        this.subjectType = subjectType;
        this.identityVerificationRequired = identityVerificationRequired;
        if (Objects.nonNull(claims)) {
            this.claims = claims;
        }
        if (Objects.isNull(clientType)) {
            clientType = ClientType.WEB.getValue();
        }
        this.clientType = clientType;
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

    public String getBackChannelLogoutUri() {
        return backChannelLogoutUri;
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

    public boolean isIdentityVerificationRequired() {
        return identityVerificationRequired;
    }

    public List<String> getClaims() {
        return claims;
    }

    public String getClientType() {
        return clientType;
    }
}
