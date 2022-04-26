package uk.gov.di.authentication.api;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
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
import uk.gov.di.authentication.app.lambda.DocAppCallbackHandler;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.CriStubExtension;
import uk.gov.di.authentication.sharedtest.extensions.DocumentAppCredentialStoreExtension;
import uk.gov.di.authentication.sharedtest.extensions.KmsKeyExtension;
import uk.gov.di.authentication.sharedtest.extensions.SnsTopicExtension;
import uk.gov.di.authentication.sharedtest.extensions.SqsQueueExtension;
import uk.gov.di.authentication.sharedtest.extensions.TokenSigningExtension;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static uk.gov.di.authentication.app.domain.DocAppAuditableEvent.DOC_APP_AUTHORISATION_RESPONSE_RECEIVED;
import static uk.gov.di.authentication.app.domain.DocAppAuditableEvent.DOC_APP_SUCCESSFUL_CREDENTIAL_RESPONSE_RECEIVED;
import static uk.gov.di.authentication.app.domain.DocAppAuditableEvent.DOC_APP_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertEventTypesReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class DocAppCallbackHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static ECKey privateKey;
    private static ECKey publicKey;

    static {
        try {
            privateKey = new ECKeyGenerator(Curve.P_256).keyID("my-key-id").generate();
            publicKey = privateKey.toPublicJWK();
        } catch (JOSEException e) {
            e.printStackTrace();
        }
    }

    @RegisterExtension
    public static final CriStubExtension criStub = new CriStubExtension(privateKey);

    @RegisterExtension
    protected static final DocumentAppCredentialStoreExtension credentialExtension =
            new DocumentAppCredentialStoreExtension();

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
                    publicKey);

    private static final String CLIENT_ID = "test-client-id";
    private static final String REDIRECT_URI = "http://localhost/redirect";

    @BeforeEach
    void setup() throws JOSEException {
        criStub.init();
        handler = new DocAppCallbackHandler(configurationService);
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
    void shouldRedirectToLoginWhenSuccessfullyProcessedIpvResponse() throws IOException {
        var sessionId = "some-session-id";
        var clientSessionId = "some-client-session-id";
        var scope = new Scope(OIDCScopeValue.OPENID);
        var state = new State();
        var authRequestBuilder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                scope,
                                new ClientID(CLIENT_ID),
                                URI.create(REDIRECT_URI))
                        .state(state)
                        .nonce(new Nonce());
        redis.createSession(sessionId);
        var clientSession =
                new ClientSession(
                        authRequestBuilder.build().toParameters(),
                        LocalDateTime.now(),
                        VectorOfTrust.getDefaults());
        clientSession.setDocAppSubjectId(new Subject());
        redis.createClientSession(clientSessionId, clientSession);
        redis.addStateToRedis(state, sessionId);

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(buildSessionCookie(sessionId, clientSessionId))),
                        constructQueryStringParameters(state));

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
    }

    private Map<String, String> constructQueryStringParameters(State state) {
        final Map<String, String> queryStringParameters = new HashMap<>();
        queryStringParameters.putAll(
                Map.of("state", state.getValue(), "code", new AuthorizationCode().getValue()));
        return queryStringParameters;
    }

    protected static class TestConfigurationService extends IntegrationTestConfigurationService {

        private final CriStubExtension criStubExtension;
        private final ECKey signingPublicKey;

        public TestConfigurationService(
                CriStubExtension criStubExtension,
                SnsTopicExtension auditEventTopic,
                SqsQueueExtension notificationQueue,
                KmsKeyExtension auditSigningKey,
                TokenSigningExtension tokenSigningKey,
                TokenSigningExtension ipvPrivateKeyJwtSigner,
                SqsQueueExtension spotQueue,
                TokenSigningExtension docAppPrivateKeyJwtSigner,
                ECKey signingPublicKey) {
            super(
                    auditEventTopic,
                    notificationQueue,
                    auditSigningKey,
                    tokenSigningKey,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner);
            this.criStubExtension = criStubExtension;
            this.signingPublicKey = signingPublicKey;
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
        public String getDocAppCredentialSigningPublicKey() {
            return signingPublicKey.toString();
        }
    }
}
