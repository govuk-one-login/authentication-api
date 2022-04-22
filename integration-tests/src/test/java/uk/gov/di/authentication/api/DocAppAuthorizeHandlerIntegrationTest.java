package uk.gov.di.authentication.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.app.entity.DocAppAuthorisationResponse;
import uk.gov.di.authentication.app.lambda.DocAppAuthorizeHandler;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static uk.gov.di.authentication.app.domain.DocAppAuditableEvent.DOC_APP_AUTHORISATION_REQUESTED;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertEventTypesReceived;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertNoAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class DocAppAuthorizeHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String SESSION_ID = "some-session-id";
    private static final String CLIENT_SESSION_ID = "some-client-session-id";
    private static final String PERSISTENT_SESSION_ID = "some-persistent-session-id";
    private static final ClientID RP_CLIENT_ID = new ClientID("test-client");
    private static final URI CALLBACK_URI = URI.create("http://localhost/callback");
    private static final URI AUTHORIZE_URI = URI.create("http://doc-app/authorize");
    private static final String DOC_APP_CLIENT_ID = "doc-app-client-id";
    private final KeyPair keyPair = generateRsaKeyPair();
    private final String publicKey =
            "-----BEGIN PUBLIC KEY-----\n"
                    + Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded())
                    + "\n-----END PUBLIC KEY-----\n";

    protected final ConfigurationService configurationService =
            new DocAppTestConfigurationService();

    @BeforeEach
    void setup() throws IOException {
        handler = new DocAppAuthorizeHandler(configurationService);
        redis.createSession(SESSION_ID);
        redis.addAuthRequestToSession(
                CLIENT_SESSION_ID,
                SESSION_ID,
                withAuthenticationRequest(RP_CLIENT_ID.getValue()).toParameters());
    }

    @Test
    void shouldReturn200WithValidDocAppAuthRequest() throws IOException {
        redis.addDocAppSubjectIdToClientSession(new Subject(), CLIENT_SESSION_ID);
        var response =
                makeRequest(
                        Optional.empty(),
                        constructFrontendHeaders(
                                SESSION_ID, CLIENT_SESSION_ID, PERSISTENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(200));

        var body =
                new ObjectMapper().readValue(response.getBody(), DocAppAuthorisationResponse.class);

        assertThat(
                body.getRedirectUri(),
                startsWith(configurationService.getDocAppAuthorisationURI().toString()));
        assertEventTypesReceived(auditTopic, List.of(DOC_APP_AUTHORISATION_REQUESTED));
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

        assertNoAuditEventsReceived(auditTopic);
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

        public DocAppTestConfigurationService() {
            super(
                    auditTopic,
                    notificationsQueue,
                    auditSigningKey,
                    tokenSigner,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner);
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
        public String getDocAppAuthEncryptionPublicKey() {
            return publicKey;
        }
    }
}
