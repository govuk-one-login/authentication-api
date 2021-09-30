package uk.gov.di.authentication.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
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
import uk.gov.di.authentication.frontendapi.entity.UpdateProfileRequest;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.authentication.helpers.RequestHelper;
import uk.gov.di.authentication.shared.entity.BaseAPIResponse;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.helpers.IdGenerator;

import java.io.IOException;
import java.net.URI;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.frontendapi.entity.UpdateProfileType.ADD_PHONE_NUMBER;
import static uk.gov.di.authentication.frontendapi.entity.UpdateProfileType.CAPTURE_CONSENT;
import static uk.gov.di.authentication.frontendapi.entity.UpdateProfileType.UPDATE_TERMS_CONDS;
import static uk.gov.di.authentication.shared.entity.SessionState.ADDED_UNVERIFIED_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.entity.SessionState.CONSENT_ADDED;
import static uk.gov.di.authentication.shared.entity.SessionState.UPDATED_TERMS_AND_CONDITIONS_ACCEPTED;

public class UpdateProfileIntegrationTest extends IntegrationTestEndpoints {

    private static final String UPDATE_PROFILE_ENDPOINT = "/update-profile";
    private static final String EMAIL_ADDRESS = "test@test.com";
    private static final String CLIENT_ID = "test-id";
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void shouldCallUpdateProfileEndpointToUpdatePhoneNumberAndReturn200()
            throws IOException {
        String sessionId = RedisHelper.createSession();
        String clientSessionId = IdGenerator.generate();
        setUpTest(sessionId, clientSessionId, SessionState.TWO_FACTOR_REQUIRED);
        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        headers.add("Session-Id", sessionId);
        headers.add("X-API-Key", FRONTEND_API_KEY);
        UpdateProfileRequest request =
                new UpdateProfileRequest(EMAIL_ADDRESS, ADD_PHONE_NUMBER, "0123456789");

        Response response =
                RequestHelper.request(
                        FRONTEND_ROOT_RESOURCE_URL, UPDATE_PROFILE_ENDPOINT, request, headers);

        assertEquals(200, response.getStatus());
        String responseString = response.readEntity(String.class);
        BaseAPIResponse baseAPIResponse =
                objectMapper.readValue(responseString, BaseAPIResponse.class);
        assertEquals(ADDED_UNVERIFIED_PHONE_NUMBER, baseAPIResponse.getSessionState());
    }

    @Test
    public void shouldCallUpdateProfileToUpdateConsentAndReturn200() throws IOException {
        String sessionId = RedisHelper.createSession();
        String clientSessionId = IdGenerator.generate();
        AuthenticationRequest authRequest =
                setUpTest(sessionId, clientSessionId, SessionState.CONSENT_REQUIRED);
        RedisHelper.createClientSession(clientSessionId, authRequest.toParameters());
        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        headers.add("Session-Id", sessionId);
        headers.add("Client-Session-Id", clientSessionId);
        headers.add("X-API-Key", FRONTEND_API_KEY);

        UpdateProfileRequest request =
                new UpdateProfileRequest(EMAIL_ADDRESS, CAPTURE_CONSENT, String.valueOf(true));

        Response response =
                ClientBuilder.newClient()
                        .target(FRONTEND_ROOT_RESOURCE_URL + UPDATE_PROFILE_ENDPOINT)
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
        String responseString = response.readEntity(String.class);
        BaseAPIResponse baseAPIResponse =
                objectMapper.readValue(responseString, BaseAPIResponse.class);
        assertEquals(CONSENT_ADDED, baseAPIResponse.getSessionState());
    }

    @Test
    public void shouldCallUpdateProfileToApproveTermsAndConditonsAndReturn200() throws IOException {
        String sessionId = RedisHelper.createSession();
        String clientSessionId = IdGenerator.generate();
        setUpTest(sessionId, clientSessionId, SessionState.UPDATED_TERMS_AND_CONDITIONS);
        MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        headers.add("Session-Id", sessionId);
        headers.add("Client-Session-Id", clientSessionId);
        headers.add("X-API-Key", FRONTEND_API_KEY);

        UpdateProfileRequest request =
                new UpdateProfileRequest(EMAIL_ADDRESS, UPDATE_TERMS_CONDS, String.valueOf(true));

        Response response =
                ClientBuilder.newClient()
                        .target(FRONTEND_ROOT_RESOURCE_URL + UPDATE_PROFILE_ENDPOINT)
                        .request(MediaType.APPLICATION_JSON)
                        .headers(headers)
                        .post(Entity.entity(request, MediaType.APPLICATION_JSON));

        assertEquals(200, response.getStatus());

        String responseString = response.readEntity(String.class);
        BaseAPIResponse baseAPIResponse =
                objectMapper.readValue(responseString, BaseAPIResponse.class);
        assertEquals(UPDATED_TERMS_AND_CONDITIONS_ACCEPTED, baseAPIResponse.getSessionState());
    }

    private AuthenticationRequest setUpTest(
            String sessionId, String clientSessionId, SessionState sessionState) {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        scope.add(OIDCScopeValue.EMAIL);
        RedisHelper.addEmailToSession(sessionId, EMAIL_ADDRESS);
        RedisHelper.setSessionState(sessionId, sessionState);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                scope,
                                new ClientID(CLIENT_ID),
                                URI.create("http://localhost/redirect"))
                        .nonce(new Nonce())
                        .build();
        RedisHelper.createClientSession(clientSessionId, authRequest.toParameters());
        DynamoHelper.registerClient(
                CLIENT_ID,
                "test-client",
                singletonList("redirect-url"),
                singletonList(EMAIL_ADDRESS),
                List.of("openid", "email"),
                "public-key",
                singletonList("http://localhost/post-redirect-logout"),
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public",
                CredentialTrustLevel.MEDIUM_LEVEL.getValue());
        Set<String> claims = ValidScopes.getClaimsForListOfScopes(scope.toStringList());
        DynamoHelper.signUp(EMAIL_ADDRESS, "password");
        DynamoHelper.updateConsent(
                EMAIL_ADDRESS,
                new ClientConsent(
                        CLIENT_ID, claims, LocalDateTime.now(ZoneId.of("UTC")).toString()));
        return authRequest;
    }
}
