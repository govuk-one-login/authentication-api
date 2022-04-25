package uk.gov.di.authentication.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
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
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
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

        registerClient(KeyPairHelper.GENERATE_RSA_KEY_PAIR(), ClientType.WEB);

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

    @Test
    void shouldReturn200WhenUserIsADocCheckingAppUser() throws IOException, JOSEException {
        var keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
        var sessionId = redis.createSession();
        var scope = new Scope(OIDCScopeValue.OPENID, CustomScopeValue.DOC_CHECKING_APP);
        var authRequest =
                new AuthorizationRequest.Builder(ResponseType.CODE, new ClientID(CLIENT_ID))
                        .requestObject(createSignedJWT(keyPair))
                        .build();
        redis.createClientSession(CLIENT_SESSION_ID, authRequest.toParameters());
        redis.createSession(sessionId);

        registerClient(keyPair, ClientType.APP);

        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);
        headers.put("X-API-Key", FRONTEND_API_KEY);

        var response = makeRequest(Optional.empty(), headers, Map.of());
        assertThat(response, hasStatus(200));

        var startResponse = objectMapper.readValue(response.getBody(), StartResponse.class);

        assertFalse(startResponse.getUser().isIdentityRequired());
        assertFalse(startResponse.getUser().isConsentRequired());
        assertFalse(startResponse.getUser().isUpliftRequired());
        assertNull(startResponse.getUser().getCookieConsent());
        assertNull(startResponse.getUser().getGaCrossDomainTrackingId());
        assertTrue(startResponse.getUser().isDocCheckingAppUser());

        assertThat(startResponse.getClient().getClientName(), equalTo(TEST_CLIENT_NAME));
        assertThat(startResponse.getClient().getServiceType(), equalTo("MANDATORY"));
        assertFalse(startResponse.getClient().getCookieConsentShared());
        assertThat(startResponse.getClient().getScopes(), equalTo(scope.toStringList()));
        assertThat(startResponse.getClient().getRedirectUri(), equalTo(REDIRECT_URI));

        var clientSession = redis.getClientSession(CLIENT_SESSION_ID);

        assertNotNull(clientSession.getDocAppSubjectId());

        assertEventTypesReceived(auditTopic, List.of(START_INFO_FOUND));
    }

    private void registerClient(KeyPair keyPair, ClientType clientType) {
        clientStore.registerClient(
                CLIENT_ID,
                TEST_CLIENT_NAME,
                singletonList(REDIRECT_URI.toString()),
                singletonList(EMAIL),
                List.of("openid", "email"),
                Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public",
                true,
                clientType);
    }

    private SignedJWT createSignedJWT(KeyPair keyPair) throws JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience("http://localhost")
                        .claim("redirect_uri", REDIRECT_URI.toString())
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim(
                                "scope",
                                new Scope(OIDCScopeValue.OPENID, CustomScopeValue.DOC_CHECKING_APP)
                                        .toString())
                        .claim("client_id", CLIENT_ID)
                        .issuer(CLIENT_ID)
                        .build();
        var jwsHeader = new JWSHeader(JWSAlgorithm.RS256);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        var signer = new RSASSASigner(keyPair.getPrivate());
        signedJWT.sign(signer);
        return signedJWT;
    }
}
