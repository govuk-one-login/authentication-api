package uk.gov.di.authentication.api;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.lambda.LogoutHandler;
import uk.gov.di.orchestration.shared.entity.ServiceType;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.net.URI;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.hasEntry;
import static uk.gov.di.authentication.oidc.domain.OidcAuditableEvent.LOG_OUT_SUCCESS;
import static uk.gov.di.orchestration.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.isRedirect;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.isRedirectTo;
import static uk.gov.di.orchestration.sharedtest.matchers.UriMatcher.baseUri;
import static uk.gov.di.orchestration.sharedtest.matchers.UriMatcher.redirectQueryParameters;

public class LogoutIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String BASE_URL = System.getenv().getOrDefault("BASE_URL", "rubbish");
    public static final String STATE = "8VAVNSxHO1HwiNDhwchQKdd7eOUK3ltKfQzwPDxu9LU";
    public static final String REDIRECT_URL = "https://rp-build.build.stubs.account.gov.uk/";
    public static final String SESSION_ID = "session-id";
    public static final String CLIENT_SESSION_ID = "client-session-id";

    @BeforeEach
    void setup() {
        handler = new LogoutHandler(TXMA_ENABLED_CONFIGURATION_SERVICE);
        txmaAuditQueue.clear();
    }

    @Test
    void shouldReturn302AndRedirectToSpecifiedClientLogoutUri()
            throws Json.JsonException, ParseException {
        var signedJWT = setupClientAndSession(SESSION_ID, CLIENT_SESSION_ID);
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        Map.of(
                                "id_token_hint",
                                signedJWT.serialize(),
                                "post_logout_redirect_uri",
                                REDIRECT_URL,
                                "state",
                                STATE));

        assertThat(response, isRedirect());
        assertThat(
                response,
                isRedirectTo(
                        allOf(
                                baseUri(URI.create(REDIRECT_URL)),
                                redirectQueryParameters(hasEntry("state", STATE)))));

        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(LOG_OUT_SUCCESS));
    }

    @Test
    void shouldRedirectToSpecifiedClientLogoutUriAndNotThrowIfClientSessionHasExpired()
            throws Json.JsonException, ParseException {
        var signedJWT = setupClientAndSession(SESSION_ID, CLIENT_SESSION_ID);
        redis.addClientSessionIdToSession("expired-client-session-id", SESSION_ID);
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        Map.of(
                                "id_token_hint",
                                signedJWT.serialize(),
                                "post_logout_redirect_uri",
                                REDIRECT_URL,
                                "state",
                                STATE));

        assertThat(response, isRedirect());
        assertThat(
                response,
                isRedirectTo(
                        allOf(
                                baseUri(URI.create(REDIRECT_URL)),
                                redirectQueryParameters(hasEntry("state", STATE)))));

        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(LOG_OUT_SUCCESS));
    }

    @Test
    void shouldRedirectToSpecifiedClientLogoutUriWhenThereIsNoActiveSession()
            throws Json.JsonException, ParseException {
        var signedJWT = setupClientAndSession(SESSION_ID, CLIENT_SESSION_ID);
        redis.addClientSessionIdToSession("expired-client-session-id", SESSION_ID);
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.empty()),
                        Map.of(
                                "id_token_hint",
                                signedJWT.serialize(),
                                "post_logout_redirect_uri",
                                REDIRECT_URL,
                                "state",
                                STATE));

        assertThat(response, isRedirect());
        assertThat(
                response,
                isRedirectTo(
                        allOf(
                                baseUri(URI.create(REDIRECT_URL)),
                                redirectQueryParameters(hasEntry("state", STATE)))));

        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(LOG_OUT_SUCCESS));
    }

    @Test
    void shouldReturn302AndRedirectToDefaultLogoutUriWhenNoIdTokenSpecified() throws Json.JsonException, ParseException {
        setupClientAndSession(SESSION_ID, CLIENT_SESSION_ID);
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        Map.of(
                                "post_logout_redirect_uri",
                                REDIRECT_URL,
                                "state",
                                STATE));

        assertThat(response, isRedirect());
        assertThat(
                response,
                isRedirectTo(
                        allOf(
                                baseUri(TEST_CONFIGURATION_SERVICE.getDefaultLogoutURI()),
                                redirectQueryParameters(hasEntry("state", STATE)))));

        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(LOG_OUT_SUCCESS));
    }

    @Test
    void shouldReturn302AndRedirectToDefaultLogoutUriWhenNoRedirectSpecified()
            throws Json.JsonException, ParseException {
        var signedJWT = setupClientAndSession(SESSION_ID, CLIENT_SESSION_ID);
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        Map.of("id_token_hint", signedJWT.serialize(), "state", STATE));

        assertThat(response, isRedirect());
        assertThat(
                response,
                isRedirectTo(
                        allOf(
                                baseUri(TEST_CONFIGURATION_SERVICE.getDefaultLogoutURI()),
                                redirectQueryParameters(hasEntry("state", STATE)))));

        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(LOG_OUT_SUCCESS));
    }

    @Test
    void shouldReturn302AndRedirectToDefaultLogoutUriWhenInvalidRedirectSpecified()
            throws Json.JsonException, ParseException {
        var signedJWT = setupClientAndSession(SESSION_ID, CLIENT_SESSION_ID);
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(buildSessionCookie(SESSION_ID, CLIENT_SESSION_ID))),
                        Map.of(
                                "id_token_hint",
                                signedJWT.serialize(),
                                "post_logout_redirect_uri",
                                "https://example.com/invalid-logout-url",
                                "state",
                                STATE));

        assertThat(response, isRedirect());
        assertThat(
                response,
                isRedirectTo(
                        allOf(
                                baseUri(TEST_CONFIGURATION_SERVICE.getDefaultLogoutURI()),
                                redirectQueryParameters(hasEntry("state", STATE)),
                                redirectQueryParameters(
                                        hasEntry("error_code", "invalid_request")))));

        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(LOG_OUT_SUCCESS));
    }

    private SignedJWT setupClientAndSession(String sessionId, String clientSessionId)
            throws ParseException, Json.JsonException {
        Nonce nonce = new Nonce();
        Date expiryDate = NowHelper.nowPlus(10, ChronoUnit.MINUTES);
        IDTokenClaimsSet idTokenClaims =
                new IDTokenClaimsSet(
                        new Issuer(BASE_URL),
                        new Subject(),
                        List.of(new Audience("client-id")),
                        expiryDate,
                        new Date());
        idTokenClaims.setNonce(nonce);
        SignedJWT signedJWT = externalTokenSigner.signJwt(idTokenClaims.toJWTClaimsSet());
        redis.createSession(sessionId);
        redis.addAuthRequestToSession(
                clientSessionId,
                sessionId,
                generateAuthRequest(nonce).toParameters(),
                "client-name");
        redis.addIDTokenToSession(clientSessionId, signedJWT.serialize());
        clientStore.registerClient(
                "client-id",
                "client-name",
                singletonList("http://localhost:8080/redirect"),
                singletonList("client-1"),
                singletonList("openid"),
                "public-key",
                singletonList(REDIRECT_URL),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public",
                true);

        return signedJWT;
    }

    private AuthenticationRequest generateAuthRequest(Nonce nonce) {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        State state = new State();
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        return new AuthenticationRequest.Builder(
                        responseType,
                        scope,
                        new ClientID("test-client"),
                        URI.create("http://localhost:8080/redirect"))
                .state(state)
                .nonce(nonce)
                .build();
    }
}
