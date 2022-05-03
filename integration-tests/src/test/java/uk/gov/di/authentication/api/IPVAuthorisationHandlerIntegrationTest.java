package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.ipv.entity.IPVAuthorisationResponse;
import uk.gov.di.authentication.ipv.lambda.IPVAuthorisationHandler;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.IPVStubExtension;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.IPV_AUTHORISATION_REQUESTED;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertEventTypesReceived;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertNoAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class IPVAuthorisationHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String SESSION_ID = "some-session-id";
    private static final String CLIENT_SESSION_ID = "some-client-session-id";
    private static final String PERSISTENT_SESSION_ID = "some-persistent-session-id";
    private static final ClientID CLIENT_ID = new ClientID("test-client");

    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private static final String IPV_DOMAIN = "https://ipv/redirect";

    private static final String TEST_EMAIL_ADDRESS = "test@emailtest.com";
    private static final String IPV_CLIENT_ID = "ipv-client-id";
    private final KeyPair keyPair = generateRsaKeyPair();
    private final String publicKey =
            "-----BEGIN PUBLIC KEY-----\n"
                    + Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded())
                    + "\n-----END PUBLIC KEY-----\n";

    @RegisterExtension public static final IPVStubExtension ipvStub = new IPVStubExtension();

    protected final ConfigurationService configurationService =
            new IPVTestConfigurationService(ipvStub);

    @BeforeEach
    void setup() throws IOException {
        ipvStub.init();
        handler = new IPVAuthorisationHandler(configurationService);
        redis.createSession(SESSION_ID);
        redis.addAuthRequestToSession(
                CLIENT_SESSION_ID,
                SESSION_ID,
                withAuthenticationRequest(CLIENT_ID.getValue()).toParameters());
    }

    @Test
    void shouldReturn200WithValidIPVAuthorisationRequest() throws IOException {
        userStore.signUp(TEST_EMAIL_ADDRESS, "password-1");
        clientStore.registerClient(
                CLIENT_ID.getValue(),
                "test-client",
                singletonList(REDIRECT_URI.toString()),
                singletonList(TEST_EMAIL_ADDRESS),
                singletonList("openid"),
                "",
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "pairwise",
                true);

        var response =
                makeRequest(
                        Optional.of(format("{ \"email\": \"%s\"}", TEST_EMAIL_ADDRESS)),
                        constructFrontendHeaders(
                                SESSION_ID, CLIENT_SESSION_ID, PERSISTENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(200));

        var body = objectMapper.readValue(response.getBody(), IPVAuthorisationResponse.class);

        assertThat(
                body.getRedirectUri(),
                startsWith(configurationService.getIPVAuthorisationURI().toString()));

        assertEventTypesReceived(auditTopic, List.of(IPV_AUTHORISATION_REQUESTED));
    }

    @Test
    void shouldReturn400WhenBodyInvalid() {
        var response =
                makeRequest(
                        Optional.of("{ \"incorrect\": \"value\"}"),
                        constructFrontendHeaders(
                                SESSION_ID, CLIENT_SESSION_ID, PERSISTENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));

        assertNoAuditEventsReceived(auditTopic);
    }

    private AuthenticationRequest withAuthenticationRequest(String clientId) {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        return new AuthenticationRequest.Builder(
                        new ResponseType(ResponseType.Value.CODE),
                        scope,
                        new ClientID(clientId),
                        REDIRECT_URI)
                .state(new State())
                .nonce(new Nonce())
                .build();
    }

    private KeyPair generateRsaKeyPair() {
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private class IPVTestConfigurationService extends IntegrationTestConfigurationService {

        private final IPVStubExtension ipvStubExtension;

        public IPVTestConfigurationService(IPVStubExtension ipvStub) {
            super(
                    auditTopic,
                    notificationsQueue,
                    auditSigningKey,
                    tokenSigner,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner);
            this.ipvStubExtension = ipvStub;
        }

        @Override
        public URI getIPVAuthorisationURI() {
            try {
                return new URIBuilder()
                        .setHost("localhost")
                        .setPort(ipvStubExtension.getHttpPort())
                        .setScheme("http")
                        .build();
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public String getIPVAuthorisationClientId() {
            return IPV_CLIENT_ID;
        }

        @Override
        public URI getIPVAuthorisationCallbackURI() {
            return REDIRECT_URI;
        }

        @Override
        public String getIPVAuthEncryptionPublicKey() {
            return publicKey;
        }

        @Override
        public String getIPVDomain() {
            return IPV_DOMAIN;
        }
    }
}
