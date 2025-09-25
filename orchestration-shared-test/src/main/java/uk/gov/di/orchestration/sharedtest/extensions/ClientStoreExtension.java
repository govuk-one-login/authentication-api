package uk.gov.di.orchestration.sharedtest.extensions;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import uk.gov.di.orchestration.shared.entity.Channel;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.PublicKeySource;
import uk.gov.di.orchestration.shared.entity.ServiceType;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.sharedtest.basetest.DynamoTestConfiguration;
import uk.gov.di.orchestration.sharedtest.utils.KeyPairUtils;

import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;

public class ClientStoreExtension extends DynamoExtension implements AfterEachCallback {

    public static final String CLIENT_REGISTRY_TABLE = "local-client-registry";
    public static final String CLIENT_ID_FIELD = "ClientID";
    public static final String CLIENT_NAME_FIELD = "ClientName";
    public static final String CLIENT_NAME_INDEX = "ClientNameIndex";

    private DynamoClientService dynamoClientService;

    public ClientRegistrationBuilder createClient() {
        return new ClientRegistrationBuilder();
    }

    public boolean clientExists(String clientID) {
        return dynamoClientService.isValidClient(clientID);
    }

    public Optional<ClientRegistry> getClient(String clientId) {
        return dynamoClientService.getClient(clientId);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);
        dynamoClientService =
                new DynamoClientService(
                        new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT));
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, CLIENT_REGISTRY_TABLE, CLIENT_ID_FIELD);
    }

    @Override
    protected void createTables() {
        if (!tableExists(CLIENT_REGISTRY_TABLE)) {
            createTableWithPartitionKey(
                    CLIENT_REGISTRY_TABLE,
                    CLIENT_ID_FIELD,
                    createGlobalSecondaryIndex(CLIENT_NAME_INDEX, CLIENT_NAME_FIELD));
        }
    }

    public class ClientRegistrationBuilder {

        private String clientID = "test-client-id";
        private String clientName = "Test Client";
        private List<String> redirectUris = singletonList("https://rp-uri/redirect");
        private List<String> contacts = singletonList("joe.bloggs@digital.cabinet-office.gov.uk");
        private List<String> scopes = singletonList("openid");
        private String publicKey =
                Base64.getMimeEncoder()
                        .encodeToString(KeyPairUtils.generateRsaKeyPair().getPublic().getEncoded());
        private List<String> postLogoutRedirectUris =
                singletonList("http://localhost/post-redirect-logout");
        private String backChannelLogoutUri = "http://example.com";
        private String serviceType = String.valueOf(ServiceType.MANDATORY);
        private String sectorIdentifierUri = "https://test.com";
        private String subjectType = "public";
        private String jwksUrl = null;
        private ClientType clientType = ClientType.WEB;
        private List<String> claims = emptyList();
        private boolean jarValidationRequired = false;
        private boolean identityVerificationSupported = false;
        private String clientSecret = null;
        private String tokenAuthMethod = ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue();
        private String idTokenSigningAlgorithm = null;
        private List<String> clientLoCs = emptyList();
        private String channel = Channel.WEB.getValue();
        private boolean maxAgeEnabled = false;
        private boolean pkceEnforced = false;
        private String landingPageUrl = null;

        public void saveToDynamo() {
            dynamoClientService.addClient(
                    clientID,
                    clientName,
                    redirectUris,
                    contacts,
                    PublicKeySource.STATIC.getValue(),
                    publicKey,
                    jwksUrl,
                    scopes,
                    postLogoutRedirectUris,
                    backChannelLogoutUri,
                    serviceType,
                    sectorIdentifierUri,
                    subjectType,
                    jarValidationRequired,
                    claims,
                    clientType.getValue(),
                    identityVerificationSupported,
                    clientSecret,
                    tokenAuthMethod,
                    idTokenSigningAlgorithm,
                    clientLoCs,
                    channel,
                    maxAgeEnabled,
                    pkceEnforced,
                    landingPageUrl);
        }

        public ClientRegistrationBuilder withClientId(String clientID) {
            this.clientID = clientID;
            return this;
        }

        public ClientRegistrationBuilder withClientName(String clientName) {
            this.clientName = clientName;
            return this;
        }

        public ClientRegistrationBuilder withRedirectUris(List<String> redirectUris) {
            this.redirectUris = redirectUris;
            return this;
        }

        public ClientRegistrationBuilder withContacts(List<String> contacts) {
            this.contacts = contacts;
            return this;
        }

        public ClientRegistrationBuilder withScopes(List<String> scopes) {
            this.scopes = scopes;
            return this;
        }

        public ClientRegistrationBuilder withPublicKey(String publicKey) {
            this.publicKey = publicKey;
            return this;
        }

        public ClientRegistrationBuilder withPostLogoutRedirectUris(
                List<String> postLogoutRedirectUris) {
            this.postLogoutRedirectUris = postLogoutRedirectUris;
            return this;
        }

        public ClientRegistrationBuilder withBackChannelLogoutUri(String backChannelLogoutUri) {
            this.backChannelLogoutUri = backChannelLogoutUri;
            return this;
        }

        public ClientRegistrationBuilder withServiceType(String serviceType) {
            this.serviceType = serviceType;
            return this;
        }

        public ClientRegistrationBuilder withSectorIdentifierUri(String sectorIdentifierUri) {
            this.sectorIdentifierUri = sectorIdentifierUri;
            return this;
        }

        public ClientRegistrationBuilder withSubjectType(String subjectType) {
            this.subjectType = subjectType;
            return this;
        }

        public ClientRegistrationBuilder withJwksUrl(String jwksUrl) {
            this.jwksUrl = jwksUrl;
            return this;
        }

        public ClientRegistrationBuilder withJarValidationRequired(boolean jarValidationRequired) {
            this.jarValidationRequired = jarValidationRequired;
            return this;
        }

        public ClientRegistrationBuilder withClaims(List<String> claims) {
            this.claims = claims;
            return this;
        }

        public ClientRegistrationBuilder withClientType(ClientType clientType) {
            this.clientType = clientType;
            return this;
        }

        public ClientRegistrationBuilder withIdentityVerificationSupported(
                boolean identityVerificationSupported) {
            this.identityVerificationSupported = identityVerificationSupported;
            return this;
        }

        public ClientRegistrationBuilder withClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        public ClientRegistrationBuilder withTokenAuthMethod(String tokenAuthMethod) {
            this.tokenAuthMethod = tokenAuthMethod;
            return this;
        }

        public ClientRegistrationBuilder withIdTokenSigningAlgorithm(
                String idTokenSigningAlgorithm) {
            this.idTokenSigningAlgorithm = idTokenSigningAlgorithm;
            return this;
        }

        public ClientRegistrationBuilder withClientLoCs(List<String> clientLoCs) {
            this.clientLoCs = clientLoCs;
            return this;
        }

        public ClientRegistrationBuilder withChannel(String channel) {
            this.channel = channel;
            return this;
        }

        public ClientRegistrationBuilder withMaxAgeEnabled(boolean maxAgeEnabled) {
            this.maxAgeEnabled = maxAgeEnabled;
            return this;
        }

        public ClientRegistrationBuilder withPkceEnforced(boolean pkceEnforced) {
            this.pkceEnforced = pkceEnforced;
            return this;
        }

        public ClientRegistrationBuilder withLandingPageUrl(String landingPageUrl) {
            this.landingPageUrl = landingPageUrl;
            return this;
        }
    }
}
