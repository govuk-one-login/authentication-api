package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.frontendapi.entity.SignUpResponse;
import uk.gov.di.authentication.frontendapi.entity.SignupRequest;
import uk.gov.di.authentication.frontendapi.lambda.SignUpHandler;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.io.IOException;
import java.net.URI;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.CREATE_ACCOUNT;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertEventTypesReceived;
import static uk.gov.di.authentication.sharedtest.helper.KeyPairHelper.GENERATE_RSA_KEY_PAIR;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class SignupIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String CLIENT_ID = "test-client-id";
    private static final String REDIRECT_URI = "http://localhost/redirect";
    public static final String CLIENT_SESSION_ID = "a-client-session-id";

    @BeforeEach
    void setup() {
        handler = new SignUpHandler(TEST_CONFIGURATION_SERVICE);
    }

    private static Stream<Boolean> consentValues() {
        return Stream.of(true, false);
    }

    @ParameterizedTest
    @MethodSource("consentValues")
    void shouldReturn200WhenValidSignUpRequest(boolean consentRequired)
            throws IOException, Json.JsonException {
        String sessionId = redis.createSession();

        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);
        headers.put("X-API-Key", FRONTEND_API_KEY);

        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);

        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                scope,
                                new ClientID(CLIENT_ID),
                                URI.create(REDIRECT_URI))
                        .nonce(new Nonce())
                        .build();

        redis.createClientSession(CLIENT_SESSION_ID, authRequest.toParameters());

        clientStore.registerClient(
                CLIENT_ID,
                "The test client",
                singletonList(REDIRECT_URI),
                singletonList("test-client@test.com"),
                singletonList(scope.toString()),
                Base64.getMimeEncoder()
                        .encodeToString(GENERATE_RSA_KEY_PAIR().getPublic().getEncoded()),
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public",
                consentRequired);

        var response =
                makeRequest(
                        Optional.of(
                                new SignupRequest(
                                        "joe.bloggs+5@digital.cabinet-office.gov.uk",
                                        "password-1")),
                        headers,
                        Map.of());

        assertThat(response, hasStatus(200));
        SignUpResponse signUpResponse =
                objectMapper.readValue(response.getBody(), SignUpResponse.class);
        assertThat(signUpResponse.isConsentRequired(), equalTo(consentRequired));

        assertTrue(userStore.userExists("joe.bloggs+5@digital.cabinet-office.gov.uk"));

        assertEventTypesReceived(auditTopic, List.of(CREATE_ACCOUNT));
    }
}
