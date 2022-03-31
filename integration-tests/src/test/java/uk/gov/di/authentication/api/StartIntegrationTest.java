package uk.gov.di.authentication.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.StartResponse;
import uk.gov.di.authentication.frontendapi.lambda.StartHandler;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.helper.KeyPairHelper;

import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.START_INFO_FOUND;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertEventTypesReceived;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertNoAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class StartIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String CLIENT_ID = "test-client-id";
    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    public static final String CLIENT_SESSION_ID = "a-client-session-id";
    public static final String TEST_CLIENT_NAME = "test-client-name";

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setup() {
        handler = new StartHandler(TEST_CONFIGURATION_SERVICE);
    }

    @Test
    void shouldReturn200AndStartResponse() throws IOException {
        String sessionId = redis.createSession();
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE, scope, new ClientID(CLIENT_ID), REDIRECT_URI)
                        .nonce(new Nonce())
                        .state(new State())
                        .build();
        redis.createClientSession(CLIENT_SESSION_ID, authRequest.toParameters());
        redis.createSession(sessionId);

        registerClient(KeyPairHelper.GENERATE_RSA_KEY_PAIR());

        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);
        headers.put("X-API-Key", FRONTEND_API_KEY);

        var response = makeRequest(Optional.empty(), headers, Map.of());
        assertThat(response, hasStatus(200));

        StartResponse startResponse =
                objectMapper.readValue(response.getBody(), StartResponse.class);

        assertThat(startResponse.getUser().isIdentityRequired(), equalTo(false));
        assertThat(startResponse.getUser().isConsentRequired(), equalTo(true));
        assertThat(startResponse.getUser().isUpliftRequired(), equalTo(false));
        assertThat(startResponse.getClient().getClientName(), equalTo(TEST_CLIENT_NAME));
        assertThat(startResponse.getClient().getServiceType(), equalTo("MANDATORY"));
        assertThat(startResponse.getClient().getCookieConsentShared(), equalTo(false));
        assertThat(startResponse.getClient().getScopes(), equalTo(scope.toStringList()));
        assertThat(startResponse.getClient().getRedirectUri(), equalTo(REDIRECT_URI));
        assertThat(startResponse.getUser().getCookieConsent(), equalTo(null));
        assertThat(startResponse.getUser().getGaCrossDomainTrackingId(), equalTo(null));

        assertEventTypesReceived(auditTopic, List.of(START_INFO_FOUND));
    }

    @Test
    void shouldReturn400WhenClientSessionIdMissing() {
        var headers = Map.of("X-API-Key", FRONTEND_API_KEY);

        var response = makeRequest(Optional.empty(), headers, Map.of());
        assertThat(response, hasStatus(400));

        assertNoAuditEventsReceived(auditTopic);
    }

    private void registerClient(KeyPair keyPair) {
        clientStore.registerClient(
                CLIENT_ID,
                TEST_CLIENT_NAME,
                singletonList(REDIRECT_URI.toString()),
                singletonList(EMAIL),
                List.of("openid", "email"),
                Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                singletonList("http://localhost/post-redirect-logout"),
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public",
                true);
    }
}
