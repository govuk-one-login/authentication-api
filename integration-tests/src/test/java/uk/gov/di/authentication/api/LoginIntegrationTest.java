package uk.gov.di.authentication.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.frontendapi.entity.LoginRequest;
import uk.gov.di.authentication.frontendapi.entity.LoginResponse;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.authentication.helpers.RequestHelper;
import uk.gov.di.authentication.shared.entity.AuthenticationValues;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.SessionState;

import java.io.IOException;
import java.net.URI;
import java.util.Base64;
import java.util.stream.Stream;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.helpers.KeyPairHelper.GENERATE_RSA_KEY_PAIR;
import static uk.gov.di.authentication.shared.entity.AuthenticationValues.HIGH_LEVEL;
import static uk.gov.di.authentication.shared.entity.AuthenticationValues.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.AuthenticationValues.MEDIUM_LEVEL;
import static uk.gov.di.authentication.shared.entity.AuthenticationValues.VERY_HIGH_LEVEL;
import static uk.gov.di.authentication.shared.entity.SessionState.AUTHENTICATED;
import static uk.gov.di.authentication.shared.entity.SessionState.AUTHENTICATION_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.LOGGED_IN;

public class LoginIntegrationTest extends IntegrationTestEndpoints {

    private static final String LOGIN_ENDPOINT = "/login";
    private static final String CLIENT_ID = "test-client-id";
    private static final String REDIRECT_URI = "http://localhost/redirect";
    public static final String CLIENT_SESSION_ID = "a-client-session-id";
    public static final String TEST_CLIENT_NAME = "test-client-name";

    private final ObjectMapper objectMapper = new ObjectMapper();

    @ParameterizedTest
    @MethodSource("vectorOfTrustEndStates")
    public void shouldReturnCorrectStateForClientsTrustLevel(
            AuthenticationValues level, SessionState expectedState) throws IOException {
        String email = "joe.bloggs+3@digital.cabinet-office.gov.uk";
        String password = "password-1";
        String phoneNumber = "01234567890";
        DynamoHelper.signUp(email, password);
        DynamoHelper.addPhoneNumber(email, phoneNumber);
        String sessionId = RedisHelper.createSession();
        RedisHelper.setSessionState(sessionId, AUTHENTICATION_REQUIRED);

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
        RedisHelper.createClientSession(CLIENT_SESSION_ID, authRequest.toParameters());
        DynamoHelper.registerClient(
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
                level == null ? null : level.getValue());

        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        headers.add("Session-Id", sessionId);
        headers.add("X-API-Key", API_KEY);
        headers.add("Client-Session-Id", CLIENT_SESSION_ID);
        Response response =
                RequestHelper.request(LOGIN_ENDPOINT, new LoginRequest(email, password), headers);

        assertEquals(200, response.getStatus());

        String responseString = response.readEntity(String.class);
        LoginResponse loginResponse = objectMapper.readValue(responseString, LoginResponse.class);
        assertEquals(expectedState, loginResponse.getSessionState());
    }

    private static Stream<Arguments> vectorOfTrustEndStates() {
        return Stream.of(
                Arguments.of(null, LOGGED_IN),
                Arguments.of(LOW_LEVEL, AUTHENTICATED),
                Arguments.of(MEDIUM_LEVEL, LOGGED_IN),
                Arguments.of(HIGH_LEVEL, LOGGED_IN),
                Arguments.of(VERY_HIGH_LEVEL, LOGGED_IN));
    }

    @Test
    public void shouldCallLoginEndpointAndReturn401henUserHasInvalidCredentials()
            throws IOException {
        String email = "joe.bloggs+4@digital.cabinet-office.gov.uk";
        String password = "password-1";
        DynamoHelper.signUp(email, "wrong-password");
        String sessionId = RedisHelper.createSession();
        RedisHelper.setSessionState(sessionId, AUTHENTICATION_REQUIRED);
        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        headers.add("Session-Id", sessionId);
        headers.add("X-API-Key", API_KEY);

        Response response =
                RequestHelper.request(LOGIN_ENDPOINT, new LoginRequest(email, password), headers);

        assertEquals(401, response.getStatus());
    }
}
