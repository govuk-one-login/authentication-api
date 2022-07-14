package uk.gov.di.authentication.api;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
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
import uk.gov.di.authentication.app.exception.UnsuccesfulCredentialResponseException;
import uk.gov.di.authentication.app.lambda.DocAppCallbackHandler;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.CriStubExtension;
import uk.gov.di.authentication.sharedtest.extensions.DocAppJwksExtension;
import uk.gov.di.authentication.sharedtest.extensions.DocumentAppCredentialStoreExtension;
import uk.gov.di.authentication.sharedtest.extensions.KmsKeyExtension;
import uk.gov.di.authentication.sharedtest.extensions.SnsTopicExtension;
import uk.gov.di.authentication.sharedtest.extensions.SqsQueueExtension;
import uk.gov.di.authentication.sharedtest.extensions.TokenSigningExtension;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.app.domain.DocAppAuditableEvent.DOC_APP_AUTHORISATION_RESPONSE_RECEIVED;
import static uk.gov.di.authentication.app.domain.DocAppAuditableEvent.DOC_APP_SUCCESSFUL_CREDENTIAL_RESPONSE_RECEIVED;
import static uk.gov.di.authentication.app.domain.DocAppAuditableEvent.DOC_APP_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED;
import static uk.gov.di.authentication.app.domain.DocAppAuditableEvent.DOC_APP_UNSUCCESSFUL_CREDENTIAL_RESPONSE_RECEIVED;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertEventTypesReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class DocAppCallbackHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    public static final String SESSION_ID = "some-session-id";
    public static final String CLIENT_SESSION_ID = "some-client-session-id";
    public static final Scope SCOPE = new Scope(OIDCScopeValue.OPENID);
    public static final State STATE = new State();
    private static final String SIGNING_KEY_ID = UUID.randomUUID().toString();
    public static Subject docAppSubjectId;
    private static final ECKey privateKey;
    private static final ECKey publicKey;

    static {
        try {
            privateKey = new ECKeyGenerator(Curve.P_256).keyID(SIGNING_KEY_ID).generate();
            publicKey = privateKey.toPublicJWK();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    @RegisterExtension public static final CriStubExtension criStub = new CriStubExtension();

    @RegisterExtension
    public static final DocAppJwksExtension jwksExtension = new DocAppJwksExtension();

    @RegisterExtension
    protected static final DocumentAppCredentialStoreExtension credentialExtension =
            new DocumentAppCredentialStoreExtension(180);

    protected final ConfigurationService configurationService =
            new DocAppCallbackHandlerIntegrationTest.TestConfigurationService(
                    criStub,
                    auditTopic,
                    notificationsQueue,
                    auditSigningKey,
                    tokenSigner,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner,
                    jwksExtension);

    private static final String CLIENT_ID = "test-client-id";
    private static final String REDIRECT_URI = "http://localhost/redirect";

    @BeforeEach
    void setup() throws JOSEException {
        criStub.init(privateKey);
        jwksExtension.init(new JWKSet(publicKey));
        handler = new DocAppCallbackHandler(configurationService);
        docAppSubjectId =
                new Subject(
                        ClientSubjectHelper.calculatePairwiseIdentifier(
                                new Subject().getValue(),
                                "https://test.com",
                                SaltHelper.generateNewSalt()));
        clientStore.registerClient(
                CLIENT_ID,
                "test-client",
                singletonList(REDIRECT_URI),
                singletonList("contact@example.com"),
                singletonList("openid"),
                null,
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "pairwise",
                true,
                ClientType.APP);
    }

    @Test
    void shouldRedirectToLoginWhenSuccessfullyProcessedDocAppResponse() throws Json.JsonException {
        setupSession();

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        constructQueryStringParameters(STATE));

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));

        assertEventTypesReceived(
                auditTopic,
                List.of(
                        DOC_APP_AUTHORISATION_RESPONSE_RECEIVED,
                        DOC_APP_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        DOC_APP_SUCCESSFUL_CREDENTIAL_RESPONSE_RECEIVED));

        var docAppCredential = documentAppCredentialStore.getCredential(docAppSubjectId.getValue());
        assertTrue(docAppCredential.isPresent());
        assertThat(docAppCredential.get().getCredential().size(), equalTo(1));
    }

    @Test
    void shouldThrowIfInvalidResponseReceivedFromCriProtectedEndpoint() throws Json.JsonException {
        setupSession();

        criStub.register("/protected-resource", 200, "application/jwt", "invalid-response");

        assertThrows(
                UnsuccesfulCredentialResponseException.class,
                () ->
                        makeRequest(
                                Optional.empty(),
                                constructHeaders(
                                        Optional.of(
                                                buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                                constructQueryStringParameters(STATE)));
        assertEventTypesReceived(
                auditTopic,
                List.of(
                        DOC_APP_AUTHORISATION_RESPONSE_RECEIVED,
                        DOC_APP_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        DOC_APP_UNSUCCESSFUL_CREDENTIAL_RESPONSE_RECEIVED));
    }

    @Test
    void shouldThrowIfErrorReceivedFromCriProtectedEndpoint() throws Json.JsonException {
        setupSession();

        criStub.register("/protected-resource", 400, "application/jwt", "error");

        assertThrows(
                UnsuccesfulCredentialResponseException.class,
                () ->
                        makeRequest(
                                Optional.empty(),
                                constructHeaders(
                                        Optional.of(
                                                buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                                constructQueryStringParameters(STATE)));

        assertEventTypesReceived(
                auditTopic,
                List.of(
                        DOC_APP_AUTHORISATION_RESPONSE_RECEIVED,
                        DOC_APP_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        DOC_APP_UNSUCCESSFUL_CREDENTIAL_RESPONSE_RECEIVED));
    }

    @Test
    void shouldThrowIfErrorBadlySignedCriResponseReceived()
            throws Json.JsonException, JOSEException {
        setupSession();
        var badPrivateKey = new ECKeyGenerator(Curve.P_256).keyID("bad-key-id").generate();

        criStub.init(badPrivateKey);

        assertThrows(
                UnsuccesfulCredentialResponseException.class,
                () ->
                        makeRequest(
                                Optional.empty(),
                                constructHeaders(
                                        Optional.of(
                                                buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                                constructQueryStringParameters(STATE)));

        assertEventTypesReceived(
                auditTopic,
                List.of(
                        DOC_APP_AUTHORISATION_RESPONSE_RECEIVED,
                        DOC_APP_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        DOC_APP_UNSUCCESSFUL_CREDENTIAL_RESPONSE_RECEIVED));
    }

    private void setupSession() throws Json.JsonException {
        var authRequestBuilder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                SCOPE,
                                new ClientID(CLIENT_ID),
                                URI.create(REDIRECT_URI))
                        .state(STATE)
                        .nonce(new Nonce());
        redis.createSession(SESSION_ID);
        var clientSession =
                new ClientSession(
                        authRequestBuilder.build().toParameters(),
                        LocalDateTime.now(),
                        VectorOfTrust.getDefaults());
        clientSession.setDocAppSubjectId(docAppSubjectId);
        redis.createClientSession(CLIENT_SESSION_ID, clientSession);
        redis.addStateToRedis(STATE, SESSION_ID);
    }

    private Map<String, String> constructQueryStringParameters(State state) {
        final Map<String, String> queryStringParameters = new HashMap<>();
        queryStringParameters.putAll(
                Map.of("state", state.getValue(), "code", new AuthorizationCode().getValue()));
        return queryStringParameters;
    }

    protected static class TestConfigurationService extends IntegrationTestConfigurationService {

        private final CriStubExtension criStubExtension;
        private final DocAppJwksExtension jwksExtension;

        public TestConfigurationService(
                CriStubExtension criStubExtension,
                SnsTopicExtension auditEventTopic,
                SqsQueueExtension notificationQueue,
                KmsKeyExtension auditSigningKey,
                TokenSigningExtension tokenSigningKey,
                TokenSigningExtension ipvPrivateKeyJwtSigner,
                SqsQueueExtension spotQueue,
                TokenSigningExtension docAppPrivateKeyJwtSigner,
                DocAppJwksExtension jwksExtension) {
            super(
                    auditEventTopic,
                    notificationQueue,
                    auditSigningKey,
                    tokenSigningKey,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner);
            this.criStubExtension = criStubExtension;
            this.jwksExtension = jwksExtension;
        }

        @Override
        public URI getDocAppBackendURI() {
            try {
                return new URIBuilder()
                        .setHost("localhost")
                        .setPort(criStubExtension.getHttpPort())
                        .setScheme("http")
                        .build();
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public String getDocAppAuthorisationClientId() {
            return CLIENT_ID;
        }

        @Override
        public URI getDocAppAuthorisationCallbackURI() {
            return URI.create("http://localhost/redirect");
        }

        @Override
        public String getDocAppCriDataEndpoint() {
            return "/protected-resource";
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
        public String getDocAppSigningKeyID() {
            return SIGNING_KEY_ID;
        }
    }
}
