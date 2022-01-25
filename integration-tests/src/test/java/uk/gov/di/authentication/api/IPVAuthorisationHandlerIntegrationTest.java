package uk.gov.di.authentication.api;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.IPVStubExtension;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class IPVAuthorisationHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String SESSION_ID = "some-session-id";
    private static final String CLIENT_SESSION_ID = "some-client-session-id";
    private static final String PERSISTENT_SESSION_ID = "some-persistent-session-id";

    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");

    private static final String TEST_EMAIL_ADDRESS = "test@emailtest.com";
    private static final String IPV_CLIENT_ID = "ipv-client-id";

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
                withAuthenticationRequest(IPV_CLIENT_ID).toParameters(),
                TEST_EMAIL_ADDRESS);
    }

    @Test
    void shouldReturn200WithValidIPVAuthorisationRequest() throws IOException {
        var response =
                makeRequest(
                        Optional.of(format("{ \"email\": \"%s\"}", TEST_EMAIL_ADDRESS)),
                        constructFrontendHeaders(
                                SESSION_ID, CLIENT_SESSION_ID, PERSISTENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(200));

        IPVAuthorisationResponse body =
                new ObjectMapper().readValue(response.getBody(), IPVAuthorisationResponse.class);

        assertEquals(body.getSessionState(), SessionState.IPV_REQUIRED);
        assertThat(
                body.getRedirectUri(),
                startsWith(configurationService.getIPVAuthorisationURI() + "/authorize"));
    }

    @Test
    void shouldReturn400WhenBodyInvalid() throws IOException {
        var response =
                makeRequest(
                        Optional.of("{ \"incorrect\": \"value\"}"),
                        constructFrontendHeaders(
                                SESSION_ID, CLIENT_SESSION_ID, PERSISTENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
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

    private class IPVTestConfigurationService extends IntegrationTestConfigurationService {

        private final IPVStubExtension ipvStubExtension;

        public IPVTestConfigurationService(IPVStubExtension ipvStub) {
            super(auditTopic, notificationsQueue, auditSigningKey, tokenSigner);
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
    }
}
