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
import uk.gov.di.authentication.frontendapi.lambda.AccountRecoveryHandler;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class AccountRecoveryIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    public static final String CLIENT_SESSION_ID = "some-client-session-id";

    @BeforeEach
    void setup() {
        handler = new AccountRecoveryHandler(TXMA_ENABLED_CONFIGURATION_SERVICE);
        txmaAuditQueue.clear();
    }

    @Test
    void shouldNotBePermittedForAccountRecoveryAndReturn200() throws Json.JsonException {
        var sessionId = redis.createSession();
        redis.addEmailToSession(sessionId, EMAIL);
        redis.createClientSession(CLIENT_SESSION_ID, createClientSession());

        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);
        var response =
                makeRequest(Optional.of(format("{ \"email\": \"%s\"}", EMAIL)), headers, Map.of());

        assertThat(response, hasStatus(200));
    }

    private ClientSession createClientSession() {
        var authRequestBuilder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                new Scope(OIDCScopeValue.OPENID),
                                new ClientID("test-client-id"),
                                URI.create("http://localhost/redirect"))
                        .state(new State())
                        .nonce(new Nonce());
        return new ClientSession(
                authRequestBuilder.build().toParameters(),
                LocalDateTime.now(),
                VectorOfTrust.getDefaults(),
                "test-client-name");
    }
}
