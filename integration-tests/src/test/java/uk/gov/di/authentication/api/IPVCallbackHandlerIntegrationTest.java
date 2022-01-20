package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.State;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.ipv.lambda.IPVCallbackHandler;
import uk.gov.di.authentication.shared.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.IPVStubExtension;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class IPVCallbackHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    @RegisterExtension public static final IPVStubExtension ipvStub = new IPVStubExtension();

    protected static final ConfigurationService configurationService =
            new IPVCallbackHandlerIntegrationTest.TestConfigurationService(ipvStub);

    private static final String TEST_EMAIL_ADDRESS = "test@test.com";

    @BeforeEach
    void setup() {
        ipvStub.init();
        handler = new IPVCallbackHandler(configurationService);
    }

    @Test
    void shouldReturn200AndClientInfoResponseForValidClient() throws IOException {
        String sessionId = "some-session-id";
        String clientSessionId = "some-client-session-id";
        State state = new State();
        redis.createSession(sessionId);
        redis.addStateToRedis(state, sessionId);
        redis.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        userStore.signUp(TEST_EMAIL_ADDRESS, "wrong-password");
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
    }

    private Map<String, String> constructQueryStringParameters(State state) {
        final Map<String, String> queryStringParameters = new HashMap<>();
        queryStringParameters.putAll(
                Map.of("state", state.getValue(), "code", new AuthorizationCode().getValue()));
        return queryStringParameters;
    }

    protected static class TestConfigurationService extends ConfigurationService {

        private final IPVStubExtension ipvStubExtension;

        public TestConfigurationService(IPVStubExtension ipvStub) {
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
            return "ipv-client-id";
        }

        @Override
        public URI getIPVAuthorisationCallbackURI() {
            return URI.create("http://localhost/redirect");
        }
    }
}
