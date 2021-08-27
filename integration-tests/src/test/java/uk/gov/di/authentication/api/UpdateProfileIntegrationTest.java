package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.entity.UpdateProfileRequest;

import java.io.IOException;
import java.net.URI;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.helpers.RequestHelper.requestWithSession;
import static uk.gov.di.entity.UpdateProfileType.ADD_PHONE_NUMBER;
import static uk.gov.di.entity.UpdateProfileType.CAPTURE_CONSENT;

public class UpdateProfileIntegrationTest extends IntegrationTestEndpoints {

    private static final String UPDATE_PROFILE_ENDPOINT = "/update-profile";
    private static final String EMAIL_ADDRESS = "test@test.com";
    private static final String CLIENT_ID = "test-id";

    @Test
    public void shouldCallUpdateProfileEndpointAndReturn200() throws IOException {
        String sessionId = RedisHelper.createSession();
        RedisHelper.addEmailToSession(sessionId, EMAIL_ADDRESS);
        RedisHelper.setSessionState(sessionId, SessionState.TWO_FACTOR_REQUIRED);
        DynamoHelper.signUp(EMAIL_ADDRESS, "password-1");

        UpdateProfileRequest request =
                new UpdateProfileRequest(EMAIL_ADDRESS, ADD_PHONE_NUMBER, "0123456789");

        Response response = requestWithSession(UPDATE_PROFILE_ENDPOINT, request, sessionId);

        assertEquals(200, response.getStatus());
    }

    @Test
    public void shouldCallUpdateProfileToUpdateConsentAndReturn200() throws IOException {
        String sessionId = RedisHelper.createSession();
        String clientSessionId = IdGenerator.generate();
        RedisHelper.addEmailToSession(sessionId, EMAIL_ADDRESS);
        RedisHelper.setSessionState(sessionId, SessionState.TWO_FACTOR_REQUIRED);
        RedisHelper.createClientSession(clientSessionId, generateAuthRequest().toParameters());
        DynamoHelper.signUp(EMAIL_ADDRESS, "password-1");

        UpdateProfileRequest request =
                new UpdateProfileRequest(EMAIL_ADDRESS, CAPTURE_CONSENT, String.valueOf(true));

        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        headers.add("Session-Id", sessionId);
        headers.add("Client-Session-Id", clientSessionId);

        Response response =
                ClientBuilder.newClient()
                        .target(ROOT_RESOURCE_URL + UPDATE_PROFILE_ENDPOINT)
                        .request(MediaType.APPLICATION_JSON)
                        .headers(headers)
                        .post(Entity.entity(request, MediaType.APPLICATION_JSON));

        assertEquals(200, response.getStatus());
        Optional<ClientConsent> consent =
                DynamoHelper.getUserConsents(EMAIL_ADDRESS)
                        .flatMap(
                                list ->
                                        list.stream()
                                                .filter(c -> c.getClientId().equals(CLIENT_ID))
                                                .findFirst());
        assertTrue(consent.get().getClaims().containsAll(OIDCScopeValue.OPENID.getClaimNames()));
        assertTrue(consent.get().getClaims().containsAll(OIDCScopeValue.EMAIL.getClaimNames()));
    }

    private AuthenticationRequest generateAuthRequest() {
        Scope scopeValues = new Scope();
        scopeValues.add("openid");
        scopeValues.add("email");
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        State state = new State();
        Nonce nonce = new Nonce();
        return new AuthenticationRequest.Builder(
                        responseType,
                        scopeValues,
                        new ClientID(CLIENT_ID),
                        URI.create("http://localhost/redirect"))
                .state(state)
                .nonce(nonce)
                .build();
    }
}
