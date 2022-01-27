package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.frontendapi.entity.LoginRequest;
import uk.gov.di.authentication.frontendapi.entity.LoginResponse;
import uk.gov.di.authentication.frontendapi.lambda.LoginHandler;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.SessionState;
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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.INVALID_CREDENTIALS;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.LOG_IN_SUCCESS;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;
import static uk.gov.di.authentication.shared.entity.SessionState.AUTHENTICATION_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.CONSENT_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.LOGGED_IN;
import static uk.gov.di.authentication.shared.entity.SessionState.UPDATED_TERMS_AND_CONDITIONS;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertEventTypesReceived;
import static uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper.jsonArrayOf;
import static uk.gov.di.authentication.sharedtest.helper.KeyPairHelper.GENERATE_RSA_KEY_PAIR;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class LoginIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String CLIENT_ID = "test-client-id";
    private static final String REDIRECT_URI = "http://localhost/redirect";
    public static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final String CURRENT_TERMS_AND_CONDITIONS = "1.0";
    private static final String OLD_TERMS_AND_CONDITIONS = "0.1";

    @BeforeEach
    void setup() {
        handler = new LoginHandler(TEST_CONFIGURATION_SERVICE);
    }

    @ParameterizedTest
    @MethodSource("vectorOfTrustEndStates")
    void shouldReturnCorrectStateForClientsTrustLevel(
            CredentialTrustLevel level,
            String termsAndConditionsVersion,
            SessionState expectedState)
            throws IOException {
        String email = "joe.bloggs+3@digital.cabinet-office.gov.uk";
        String password = "password-1";
        String phoneNumber = "01234567890";
        userStore.signUp(email, password);
        userStore.addPhoneNumber(email, phoneNumber);
        userStore.updateTermsAndConditions(email, termsAndConditionsVersion);
        String sessionId = redis.createSession();
        redis.setSessionState(sessionId, AUTHENTICATION_REQUIRED);

        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);

        AuthenticationRequest.Builder builder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                scope,
                                new ClientID(CLIENT_ID),
                                URI.create(REDIRECT_URI))
                        .nonce(new Nonce());
        if (level != null) {
            builder.customParameter("vtr", jsonArrayOf(level.getValue()));
        }
        AuthenticationRequest authRequest = builder.build();
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
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public",
                true);

        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);

        var response =
                makeRequest(Optional.of(new LoginRequest(email, password)), headers, Map.of());
        assertThat(response, hasStatus(200));

        LoginResponse loginResponse =
                objectMapper.readValue(response.getBody(), LoginResponse.class);
        assertEquals(expectedState, loginResponse.getSessionState());

        assertEventTypesReceived(auditTopic, List.of(LOG_IN_SUCCESS));
    }

    private static Stream<Arguments> vectorOfTrustEndStates() {
        return Stream.of(
                Arguments.of(null, CURRENT_TERMS_AND_CONDITIONS, LOGGED_IN),
                Arguments.of(LOW_LEVEL, CURRENT_TERMS_AND_CONDITIONS, CONSENT_REQUIRED),
                Arguments.of(MEDIUM_LEVEL, CURRENT_TERMS_AND_CONDITIONS, LOGGED_IN),
                Arguments.of(null, OLD_TERMS_AND_CONDITIONS, LOGGED_IN),
                Arguments.of(LOW_LEVEL, OLD_TERMS_AND_CONDITIONS, UPDATED_TERMS_AND_CONDITIONS),
                Arguments.of(MEDIUM_LEVEL, OLD_TERMS_AND_CONDITIONS, LOGGED_IN));
    }

    @Test
    void shouldCallLoginEndpointAndReturn401henUserHasInvalidCredentials() throws IOException {
        String email = "joe.bloggs+4@digital.cabinet-office.gov.uk";
        String password = "password-1";
        userStore.signUp(email, "wrong-password");
        String sessionId = redis.createSession();
        redis.setSessionState(sessionId, AUTHENTICATION_REQUIRED);
        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("X-API-Key", FRONTEND_API_KEY);

        var response =
                makeRequest(Optional.of(new LoginRequest(email, password)), headers, Map.of());
        assertThat(response, hasStatus(401));

        assertEventTypesReceived(auditTopic, List.of(INVALID_CREDENTIALS));
    }
}
