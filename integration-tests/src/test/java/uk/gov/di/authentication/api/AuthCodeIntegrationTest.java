package uk.gov.di.authentication.api;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.entity.AuthCodeResponse;
import uk.gov.di.authentication.oidc.lambda.AuthCodeHandler;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.CustomScopeValue;
import uk.gov.di.orchestration.shared.entity.MFAMethodType;
import uk.gov.di.orchestration.shared.entity.ServiceType;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.orchestration.sharedtest.helper.KeyPairHelper;

import java.net.URI;
import java.security.KeyPair;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.oidc.domain.OidcAuditableEvent.AUTH_CODE_ISSUED;
import static uk.gov.di.orchestration.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class AuthCodeIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final URI REDIRECT_URI =
            URI.create(System.getenv("STUB_RELYING_PARTY_REDIRECT_URI"));
    private static final ClientID CLIENT_ID = new ClientID("test-client");
    private static final String CLIENT_NAME = "some-client-name";
    private final KeyPair keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
    private static final State STATE = new State();
    private static final Nonce NONCE = new Nonce();

    @BeforeEach
    void setup() {
        handler = new AuthCodeHandler(TXMA_ENABLED_CONFIGURATION_SERVICE);
        txmaAuditQueue.clear();
    }

    @Test
    void shouldReturn200WithSuccessfulAuthResponse() throws Json.JsonException {
        var clientSessionId = "some-client-session-id";
        var sessionID = redis.createSession();
        redis.addEmailToSession(sessionID, EMAIL);
        redis.setVerifiedMfaMethodType(sessionID, MFAMethodType.AUTH_APP);
        redis.addAuthRequestToSession(
                clientSessionId, sessionID, generateAuthRequest().toParameters(), CLIENT_NAME);
        userStore.signUp(EMAIL, "password");
        registerClient(new Scope(OIDCScopeValue.OPENID));
        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionID);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        headers.put("Client-Session-Id", clientSessionId);

        var response = makeRequest(Optional.empty(), headers, Map.of());

        assertThat(response, hasStatus(200));

        var authCodeResponse = objectMapper.readValue(response.getBody(), AuthCodeResponse.class);
        assertThat(
                authCodeResponse.getLocation(),
                startsWith(
                        "https://di-auth-stub-relying-party-build.london.cloudapps.digital/?code="));

        assertTrue(redis.getSession(sessionID).isAuthenticated());
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_CODE_ISSUED));
    }

    @Test
    void shouldReturn200WithSuccessfulAuthResponseForDocAppJourney()
            throws Json.JsonException, JOSEException {
        var clientSessionId = "some-client-session-id";
        var sessionID = redis.createSession();
        Map<String, List<String>> authRequestParams = generateDocAppAuthRequest().toParameters();
        var clientSession =
                new ClientSession(
                        authRequestParams,
                        LocalDateTime.now(ZoneId.of("UTC")),
                        VectorOfTrust.getDefaults(),
                        CLIENT_NAME);
        clientSession.setDocAppSubjectId(new Subject());
        redis.addAuthRequestToSession(clientSessionId, sessionID, authRequestParams, CLIENT_NAME);
        redis.createClientSession(clientSessionId, clientSession);
        registerClient(new Scope(OIDCScopeValue.OPENID, CustomScopeValue.DOC_CHECKING_APP));

        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionID);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        headers.put("Client-Session-Id", clientSessionId);

        var response = makeRequest(Optional.empty(), headers, Map.of());

        assertThat(response, hasStatus(200));

        var authCodeResponse = objectMapper.readValue(response.getBody(), AuthCodeResponse.class);
        assertThat(
                authCodeResponse.getLocation(),
                startsWith(
                        "https://di-auth-stub-relying-party-build.london.cloudapps.digital/?code="));

        assertFalse(redis.getSession(sessionID).isAuthenticated());
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_CODE_ISSUED));
    }

    private AuthenticationRequest generateAuthRequest() {
        var responseType = new ResponseType(ResponseType.Value.CODE);
        var scope = new Scope(OIDCScopeValue.OPENID);
        return new AuthenticationRequest.Builder(responseType, scope, CLIENT_ID, REDIRECT_URI)
                .state(STATE)
                .nonce(NONCE)
                .build();
    }

    private AuthenticationRequest generateDocAppAuthRequest() throws JOSEException {
        var jwtClaimsSetBuilder =
                new JWTClaimsSet.Builder()
                        .audience("http://localhost/authorize")
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim(
                                "scope",
                                new Scope(OIDCScopeValue.OPENID, CustomScopeValue.DOC_CHECKING_APP)
                                        .toString())
                        .claim("nonce", new Nonce().getValue())
                        .claim("client_id", CLIENT_ID)
                        .claim("state", new State().getValue())
                        .issuer(CLIENT_ID.getValue());
        var jwsHeader = new JWSHeader(JWSAlgorithm.RS256);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSetBuilder.build());
        var signer = new RSASSASigner(keyPair.getPrivate());
        signedJWT.sign(signer);
        var scope = new Scope(OIDCScopeValue.OPENID, CustomScopeValue.DOC_CHECKING_APP);
        return new AuthenticationRequest.Builder(ResponseType.CODE, scope, CLIENT_ID, REDIRECT_URI)
                .state(STATE)
                .nonce(NONCE)
                .requestObject(signedJWT)
                .build();
    }

    private void registerClient(Scope scope) {
        clientStore.registerClient(
                CLIENT_ID.getValue(),
                CLIENT_NAME,
                singletonList(REDIRECT_URI.toString()),
                singletonList(EMAIL),
                scope.toStringList(),
                Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public",
                true);
    }
}
