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
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.io.IOException;
import java.net.URI;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.hasEntry;
import static uk.gov.di.authentication.oidc.domain.OidcAuditableEvent.LOG_OUT_SUCCESS;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertEventTypesReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.isRedirect;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.isRedirectTo;
import static uk.gov.di.authentication.sharedtest.matchers.UriMatcher.baseUri;
import static uk.gov.di.authentication.sharedtest.matchers.UriMatcher.redirectQueryParameters;

public class LogoutIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String BASE_URL = System.getenv().getOrDefault("BASE_URL", "rubbish");
    public static final String STATE = "8VAVNSxHO1HwiNDhwchQKdd7eOUK3ltKfQzwPDxu9LU";
    public static final String REDIRECT_URL =
            "https://di-auth-stub-relying-party-build.london.cloudapps.digital/";
    public static final String SESSION_ID = "session-id";
    public static final String CLIENT_SESSION_ID = "client-session-id";

    @BeforeEach
    void setup() {
        handler = new LogoutHandler(TEST_CONFIGURATION_SERVICE);
    }

    @Test
    void shouldReturn302AndRedirectToSpecifiedClientLogoutUri() throws IOException, ParseException {
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

        assertEventTypesReceived(auditTopic, List.of(LOG_OUT_SUCCESS));
    }

    @Test
    void shouldReturn302AndRedirectToDefaultLogoutUriWhenNoRedirectSpecified()
            throws IOException, ParseException {
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

        assertEventTypesReceived(auditTopic, List.of(LOG_OUT_SUCCESS));
    }

    @Test
    void shouldReturn302AndRedirectToDefaultLogoutUriWhenInvalidRedirectSpecified()
            throws IOException, ParseException {
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

        assertEventTypesReceived(auditTopic, List.of(LOG_OUT_SUCCESS));
    }

    private SignedJWT setupClientAndSession(String sessionId, String clientSessionId)
            throws ParseException, IOException {
        Nonce nonce = new Nonce();
        LocalDateTime localDateTime = LocalDateTime.now().plusMinutes(10);
        Date expiryDate = Date.from(localDateTime.atZone(ZoneId.of("UTC")).toInstant());
        IDTokenClaimsSet idTokenClaims =
                new IDTokenClaimsSet(
                        new Issuer(BASE_URL),
                        new Subject(),
                        List.of(new Audience("client-id")),
                        expiryDate,
                        new Date());
        idTokenClaims.setNonce(nonce);
        SignedJWT signedJWT = tokenSigner.signJwt(idTokenClaims.toJWTClaimsSet());
        redis.createSession(sessionId);
        redis.addAuthRequestToSession(
                clientSessionId,
                sessionId,
                generateAuthRequest(nonce).toParameters(),
                "joe.bloggs@digital.cabinet-office.gov.uk");
        redis.addIDTokenToSession(clientSessionId, signedJWT.serialize());
        clientStore.registerClient(
                "client-id",
                "client-name",
                singletonList("http://localhost:8080/redirect"),
                singletonList("client-1"),
                singletonList("openid"),
                "public-key",
                singletonList(REDIRECT_URL),
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
