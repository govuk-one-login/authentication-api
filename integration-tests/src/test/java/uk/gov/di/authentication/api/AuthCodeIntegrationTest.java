package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.entity.AuthCodeResponse;
import uk.gov.di.authentication.oidc.lambda.AuthCodeHandler;
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
import static org.hamcrest.Matchers.startsWith;
import static uk.gov.di.authentication.oidc.domain.OidcAuditableEvent.AUTH_CODE_ISSUED;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertEventTypesReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class AuthCodeIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final URI REDIRECT_URI =
            URI.create(System.getenv("STUB_RELYING_PARTY_REDIRECT_URI"));
    private static final ClientID CLIENT_ID = new ClientID("test-client");

    @BeforeEach
    void setup() {
        handler = new AuthCodeHandler(TEST_CONFIGURATION_SERVICE);
    }

    @Test
    public void shouldReturn302WithSuccessfulAuthorisationResponse() throws IOException {
        String sessionId = "some-session-id";
        String clientSessionId = "some-client-session-id";
        KeyPair keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
        redis.createSession(sessionId);
        redis.addAuthRequestToSession(
                clientSessionId, sessionId, generateAuthRequest().toParameters());
        setUpDynamo(keyPair);
        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        headers.put("Client-Session-Id", clientSessionId);

        var response = makeRequest(Optional.empty(), headers, Map.of());

        assertThat(response, hasStatus(200));

        AuthCodeResponse authCodeResponse =
                objectMapper.readValue(response.getBody(), AuthCodeResponse.class);

        assertThat(
                authCodeResponse.getLocation(),
                startsWith(
                        "https://di-auth-stub-relying-party-build.london.cloudapps.digital/?code="));

        assertEventTypesReceived(auditTopic, List.of(AUTH_CODE_ISSUED));
    }

    private AuthenticationRequest generateAuthRequest() {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        State state = new State();
        Scope scope = new Scope();
        Nonce nonce = new Nonce();
        scope.add(OIDCScopeValue.OPENID);
        return new AuthenticationRequest.Builder(responseType, scope, CLIENT_ID, REDIRECT_URI)
                .state(state)
                .nonce(nonce)
                .build();
    }

    private void setUpDynamo(KeyPair keyPair) {
        clientStore.registerClient(
                CLIENT_ID.getValue(),
                "test-client",
                singletonList(REDIRECT_URI.toString()),
                singletonList(EMAIL),
                singletonList("openid"),
                Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public",
                true);
    }
}
