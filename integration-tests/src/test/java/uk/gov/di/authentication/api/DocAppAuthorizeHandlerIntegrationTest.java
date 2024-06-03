package uk.gov.di.authentication.api;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.app.entity.DocAppAuthorisationResponse;
import uk.gov.di.authentication.app.lambda.DocAppAuthorizeHandler;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.ServiceType;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.orchestration.sharedtest.extensions.DocAppJwksExtension;
import uk.gov.di.orchestration.sharedtest.helper.AuditAssertionsHelper;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static uk.gov.di.authentication.app.domain.DocAppAuditableEvent.DOC_APP_AUTHORISATION_REQUESTED;
import static uk.gov.di.orchestration.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class DocAppAuthorizeHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String SESSION_ID = "some-session-id";
    private static final String CLIENT_SESSION_ID = "some-client-session-id";
    private static final String PERSISTENT_SESSION_ID = "some-persistent-session-id";
    private static final ClientID RP_CLIENT_ID = new ClientID("test-client");
    private static final String RP_CLIENT_NAME = "test-client-name";

    private static final URI CALLBACK_URI = URI.create("http://localhost/callback");
    private static final URI AUTHORIZE_URI = URI.create("http://doc-app/authorize");
    private static final String DOC_APP_CLIENT_ID = "doc-app-client-id";
    private final KeyPair keyPair = generateRsaKeyPair();
    private static final String ENCRYPTION_KEY_ID = UUID.randomUUID().toString();

    @RegisterExtension
    public static final DocAppJwksExtension jwksExtension = new DocAppJwksExtension();

    protected final ConfigurationService configurationService =
            new DocAppTestConfigurationService(jwksExtension);

    @BeforeEach
    void setup() throws Json.JsonException {
        var jwkKey =
                new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                        .keyUse(KeyUse.ENCRYPTION)
                        .keyID(ENCRYPTION_KEY_ID)
                        .build();
        jwksExtension.init(new JWKSet(jwkKey));
        handler = new DocAppAuthorizeHandler(configurationService);
        redis.createSession(SESSION_ID);
        redis.addAuthRequestToSession(
                CLIENT_SESSION_ID,
                SESSION_ID,
                withAuthenticationRequest(RP_CLIENT_ID.getValue()).toParameters(),
                RP_CLIENT_NAME);
        txmaAuditQueue.clear();
    }

    @Test
    void shouldReturn200WithValidDocAppAuthRequest() throws Json.JsonException {
        redis.addDocAppSubjectIdToClientSession(new Subject(), CLIENT_SESSION_ID);
        clientStore.registerClient(
                RP_CLIENT_ID.getValue(),
                "test-client",
                singletonList("http://localhost/redirect"),
                singletonList("contact@example.com"),
                singletonList("openid"),
                null,
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "pairwise",
                ClientType.APP,
                false);

        var response =
                makeRequest(
                        Optional.empty(),
                        constructFrontendHeaders(
                                SESSION_ID, CLIENT_SESSION_ID, PERSISTENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(200));

        var body = objectMapper.readValue(response.getBody(), DocAppAuthorisationResponse.class);

        assertThat(
                body.getRedirectUri(),
                startsWith(configurationService.getDocAppAuthorisationURI().toString()));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(DOC_APP_AUTHORISATION_REQUESTED));
    }

    @Test
    void shouldReturn400WhenSessionIdIsInvalid() {
        var response =
                makeRequest(
                        Optional.empty(),
                        constructFrontendHeaders(
                                "invalid-session-id", CLIENT_SESSION_ID, PERSISTENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));

        AuditAssertionsHelper.assertNoTxmaAuditEventsReceived(txmaAuditQueue);
    }

    private AuthenticationRequest withAuthenticationRequest(String clientId) {
        return new AuthenticationRequest.Builder(
                        new ResponseType(ResponseType.Value.CODE),
                        new Scope(OIDCScopeValue.OPENID),
                        new ClientID(clientId),
                        CALLBACK_URI)
                .state(new State())
                .nonce(new Nonce())
                .build();
    }

    private KeyPair generateRsaKeyPair() {
        try {
            var kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private class DocAppTestConfigurationService extends IntegrationTestConfigurationService {

        private final DocAppJwksExtension jwksExtension;

        public DocAppTestConfigurationService(DocAppJwksExtension jwksExtension) {
            super(
                    externalTokenSigner,
                    storageTokenSigner,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters);
            this.jwksExtension = jwksExtension;
        }

        @Override
        public String getDocAppAuthorisationClientId() {
            return DOC_APP_CLIENT_ID;
        }

        @Override
        public URI getDocAppAuthorisationURI() {
            return AUTHORIZE_URI;
        }

        @Override
        public URI getDocAppAuthorisationCallbackURI() {
            return CALLBACK_URI;
        }

        @Override
        public URI getDocAppJwksUri() {
            try {
                return new URIBuilder()
                        .setHost("localhost")
                        .setPort(jwksExtension.getHttpPort())
                        .setPath("/.well-known/jwks.json")
                        .setScheme("http")
                        .build();
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public String getDocAppEncryptionKeyID() {
            return ENCRYPTION_KEY_ID;
        }

        @Override
        public String getTxmaAuditQueueUrl() {
            return txmaAuditQueue.getQueueUrl();
        }
    }
}
