package uk.gov.di.authentication.api;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCError;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.lambda.AuthorisationHandler;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.helper.KeyPairHelper;

import java.net.HttpCookie;
import java.net.URI;
import java.security.KeyPair;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static com.nimbusds.openid.connect.sdk.OIDCScopeValue.OPENID;
import static com.nimbusds.openid.connect.sdk.Prompt.Type.LOGIN;
import static com.nimbusds.openid.connect.sdk.Prompt.Type.NONE;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static uk.gov.di.authentication.oidc.domain.OidcAuditableEvent.AUTHORISATION_INITIATED;
import static uk.gov.di.authentication.oidc.domain.OidcAuditableEvent.AUTHORISATION_REQUEST_ERROR;
import static uk.gov.di.authentication.oidc.domain.OidcAuditableEvent.AUTHORISATION_REQUEST_RECEIVED;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;
import static uk.gov.di.authentication.shared.helpers.CookieHelper.getHttpCookieFromMultiValueResponseHeaders;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertEventTypesReceived;
import static uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper.jsonArrayOf;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthorisationIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String CLIENT_ID = "test-client";
    private static final String AM_CLIENT_ID = "am-test-client";
    private static final String INVALID_CLIENT_ID = "invalid-test-client";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_PASSWORD = "password";
    private static final KeyPair KEY_PAIR = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
    public static final String DUMMY_CLIENT_SESSION_ID = "456";

    @BeforeEach
    void setup() {
        registerClient(CLIENT_ID, "test-client", singletonList("openid"));
        handler = new AuthorisationHandler(TEST_CONFIGURATION_SERVICE);
    }

    @Test
    void shouldReturnUnmetAuthenticationRequirementsErrorWhenUsingInvalidClient() throws Exception {
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(Optional.empty()),
                        constructQueryStringParameters(
                                Optional.of(INVALID_CLIENT_ID),
                                Optional.empty(),
                                "openid",
                                Optional.empty()));

        assertThat(response, hasStatus(302));
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                containsString(OAuth2Error.UNAUTHORIZED_CLIENT.getCode()));

        assertEventTypesReceived(
                auditTopic, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_REQUEST_ERROR));
    }

    @Test
    void shouldRedirectToLoginWhenNoCookie() {
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(Optional.empty()),
                        constructQueryStringParameters(
                                Optional.of(CLIENT_ID),
                                Optional.empty(),
                                "openid",
                                Optional.of("Cl.Cm")));
        assertThat(response, hasStatus(302));
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));
        assertThat(
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs")
                        .isPresent(),
                equalTo(true));

        assertEventTypesReceived(
                auditTopic, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldRedirectToLoginWhenNoCookieAndIdentityVectorsAreIncludedInRequest() {
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(Optional.empty()),
                        constructQueryStringParameters(
                                Optional.of(CLIENT_ID),
                                Optional.empty(),
                                "openid",
                                Optional.of("P2.Cl.Cm")));
        assertThat(response, hasStatus(302));
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));
        assertThat(
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs")
                        .isPresent(),
                equalTo(true));

        assertEventTypesReceived(
                auditTopic, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldRedirectToLoginWithSamePersistentCookieValueInRequest() {
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(
                                        new HttpCookie(
                                                "di-persistent-session-id",
                                                "persistent-id-value"))),
                        constructQueryStringParameters(
                                Optional.of(CLIENT_ID),
                                Optional.empty(),
                                "openid",
                                Optional.of("Cl.Cm")));
        assertThat(response, hasStatus(302));
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));
        assertThat(
                response.getMultiValueHeaders().get(ResponseHeaders.SET_COOKIE).size(), equalTo(2));
        assertThat(
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs")
                        .isPresent(),
                equalTo(true));
        var persistentCookie =
                getHttpCookieFromMultiValueResponseHeaders(
                        response.getMultiValueHeaders(), "di-persistent-session-id");
        assertThat(persistentCookie.isPresent(), equalTo(true));
        assertThat(persistentCookie.get().getValue(), equalTo("persistent-id-value"));

        assertEventTypesReceived(
                auditTopic, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldRedirectToLoginForAccountManagementClient() {
        registerClient(AM_CLIENT_ID, "am-client-name", List.of("openid", "am"));
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(Optional.empty()),
                        constructQueryStringParameters(
                                Optional.of(AM_CLIENT_ID),
                                Optional.empty(),
                                "openid am",
                                Optional.empty()));

        assertThat(response, hasStatus(302));
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));
        assertThat(
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs")
                        .isPresent(),
                equalTo(true));
        assertThat(
                getHttpCookieFromMultiValueResponseHeaders(
                                response.getMultiValueHeaders(), "di-persistent-session-id")
                        .isPresent(),
                equalTo(true));

        assertEventTypesReceived(
                auditTopic, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldReturnInvalidScopeErrorWhenNotAccountManagementClient() {
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(Optional.empty()),
                        constructQueryStringParameters(
                                Optional.of(CLIENT_ID),
                                Optional.empty(),
                                "openid am",
                                Optional.empty()));
        assertThat(response, hasStatus(302));
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                containsString(
                        "error=invalid_scope&error_description=Invalid%2C+unknown+or+malformed+scope"));

        assertEventTypesReceived(
                auditTopic, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_REQUEST_ERROR));
    }

    @Test
    void shouldRedirectToLoginWhenBadCookie() {
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(Optional.of(new HttpCookie("gs", "this is bad"))),
                        constructQueryStringParameters(
                                Optional.of(CLIENT_ID),
                                Optional.empty(),
                                "openid",
                                Optional.empty()));
        assertThat(response, hasStatus(302));
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));
        assertThat(
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs")
                        .isPresent(),
                equalTo(true));
        assertThat(
                getHttpCookieFromMultiValueResponseHeaders(
                                response.getMultiValueHeaders(), "di-persistent-session-id")
                        .isPresent(),
                equalTo(true));

        assertEventTypesReceived(
                auditTopic, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldRedirectToLoginWhenCookieHasUnknownSessionId() {
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(buildSessionCookie("123", DUMMY_CLIENT_SESSION_ID))),
                        constructQueryStringParameters(
                                Optional.of(CLIENT_ID),
                                Optional.empty(),
                                "openid",
                                Optional.empty()));
        assertThat(response, hasStatus(302));
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));
        assertThat(
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs")
                        .isPresent(),
                equalTo(true));
        assertThat(
                getHttpCookieFromMultiValueResponseHeaders(
                                response.getMultiValueHeaders(), "di-persistent-session-id")
                        .isPresent(),
                equalTo(true));

        assertEventTypesReceived(
                auditTopic, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldRedirectToLoginWhenSessionFromCookieIsNotAuthenticated() throws Exception {
        String sessionId = givenAnExistingSession(MEDIUM_LEVEL);
        redis.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        registerUserWithConsentedScope(Optional.empty());

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(
                                        buildSessionCookie(sessionId, DUMMY_CLIENT_SESSION_ID))),
                        constructQueryStringParameters(
                                Optional.of(CLIENT_ID),
                                Optional.empty(),
                                "openid",
                                Optional.empty()));
        assertThat(response, hasStatus(302));
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));
        var cookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs");
        assertThat(
                getHttpCookieFromMultiValueResponseHeaders(
                                response.getMultiValueHeaders(), "di-persistent-session-id")
                        .isPresent(),
                equalTo(true));
        assertThat(cookie.isPresent(), equalTo(true));
        assertThat(cookie.get().getValue(), not(startsWith(sessionId)));

        assertEventTypesReceived(
                auditTopic, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldIssueAuthorisationCodeWhenSessionFromCookieIsAuthenticated() throws Exception {
        String sessionId = givenAnExistingSession(MEDIUM_LEVEL);
        redis.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        registerUserWithConsentedScope(Optional.of(new Scope(OPENID)));

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(
                                        buildSessionCookie(sessionId, DUMMY_CLIENT_SESSION_ID))),
                        constructQueryStringParameters(
                                Optional.of(CLIENT_ID),
                                Optional.empty(),
                                "openid",
                                Optional.empty()));
        assertThat(response, hasStatus(302));

        // TODO: Update assertions to reflect code issuance, once we've written that code
        var cookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs");
        assertThat(
                getHttpCookieFromMultiValueResponseHeaders(
                                response.getMultiValueHeaders(), "di-persistent-session-id")
                        .isPresent(),
                equalTo(true));
        assertThat(cookie.isPresent(), equalTo(true));
        assertThat(cookie.get().getValue(), not(startsWith(sessionId)));

        assertEventTypesReceived(
                auditTopic, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldReturnLoginRequiredErrorWhenPromptNoneAndUserUnauthenticated() {
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(Optional.empty()),
                        constructQueryStringParameters(
                                Optional.of(CLIENT_ID),
                                Optional.of(NONE.toString()),
                                "openid",
                                Optional.empty()));
        assertThat(response, hasStatus(302));
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                containsString(OIDCError.LOGIN_REQUIRED_CODE));

        assertEventTypesReceived(
                auditTopic, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_REQUEST_ERROR));
    }

    @Test
    void shouldNotPromptForLoginWhenPromptNoneAndUserAuthenticated() throws Exception {
        String sessionId = givenAnExistingSession(MEDIUM_LEVEL);
        redis.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        registerUserWithConsentedScope(Optional.of(new Scope(OPENID)));

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(
                                        buildSessionCookie(sessionId, DUMMY_CLIENT_SESSION_ID))),
                        constructQueryStringParameters(
                                Optional.of(CLIENT_ID),
                                Optional.of(NONE.toString()),
                                OPENID.getValue(),
                                Optional.empty()));

        assertThat(response, hasStatus(302));
        var cookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs");
        assertThat(
                getHttpCookieFromMultiValueResponseHeaders(
                                response.getMultiValueHeaders(), "di-persistent-session-id")
                        .isPresent(),
                equalTo(true));
        assertThat(cookie.isPresent(), equalTo(true));
        assertThat(cookie.get().getValue(), not(startsWith(sessionId)));
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));

        assertEventTypesReceived(
                auditTopic, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldPromptForLoginWhenPromptLoginAndUserAuthenticated() throws Exception {
        String sessionId = givenAnExistingSession(MEDIUM_LEVEL);
        redis.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        registerUserWithConsentedScope(Optional.empty());

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(
                                        buildSessionCookie(sessionId, DUMMY_CLIENT_SESSION_ID))),
                        constructQueryStringParameters(
                                Optional.of(CLIENT_ID),
                                Optional.of(LOGIN.toString()),
                                OPENID.getValue(),
                                Optional.empty()));

        assertThat(response, hasStatus(302));
        var cookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs");
        assertThat(
                getHttpCookieFromMultiValueResponseHeaders(
                                response.getMultiValueHeaders(), "di-persistent-session-id")
                        .isPresent(),
                equalTo(true));
        assertThat(cookie.isPresent(), equalTo(true));
        assertThat(cookie.get().getValue(), not(startsWith(sessionId)));
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));
        String newSessionId = cookie.get().getValue().split("\\.")[0];
        assertThat(redis.getSession(newSessionId).getState(), equalTo(AUTHENTICATION_REQUIRED));

        assertEventTypesReceived(
                auditTopic, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldRequireUpliftWhenHighCredentialLevelOfTrustRequested() throws Exception {
        String sessionId = givenAnExistingSession(LOW_LEVEL);
        redis.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        registerUserWithConsentedScope(Optional.empty());

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(
                                        buildSessionCookie(sessionId, DUMMY_CLIENT_SESSION_ID))),
                        constructQueryStringParameters(
                                Optional.of(CLIENT_ID),
                                Optional.empty(),
                                OPENID.getValue(),
                                Optional.of(MEDIUM_LEVEL.getValue())));

        assertThat(response, hasStatus(302));

        var cookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs");
        assertThat(
                getHttpCookieFromMultiValueResponseHeaders(
                                response.getMultiValueHeaders(), "di-persistent-session-id")
                        .isPresent(),
                equalTo(true));
        assertThat(cookie.isPresent(), equalTo(true));
        assertThat(cookie.get().getValue(), not(startsWith(sessionId)));

        String redirectUri = getHeaderValueByParamName(response, ResponseHeaders.LOCATION);
        assertThat(redirectUri, startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));
        assertThat(URI.create(redirectUri).getQuery(), equalTo("interrupt=UPLIFT_REQUIRED_CM"));

        assertEventTypesReceived(
                auditTopic, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldRequireConsentWhenUserAuthenticatedAndConsentIsNotGiven() throws Exception {
        String sessionId = givenAnExistingSession(MEDIUM_LEVEL);
        redis.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        registerUserWithConsentedScope(Optional.empty());

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(
                                        buildSessionCookie(sessionId, DUMMY_CLIENT_SESSION_ID))),
                        constructQueryStringParameters(
                                Optional.of(CLIENT_ID),
                                Optional.of(NONE.toString()),
                                OPENID.getValue(),
                                Optional.empty()));

        assertThat(response, hasStatus(302));

        var cookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs");
        assertThat(
                getHttpCookieFromMultiValueResponseHeaders(
                                response.getMultiValueHeaders(), "di-persistent-session-id")
                        .isPresent(),
                equalTo(true));
        assertThat(cookie.isPresent(), equalTo(true));
        assertThat(cookie.get().getValue(), not(startsWith(sessionId)));

        String redirectUri = getHeaderValueByParamName(response, ResponseHeaders.LOCATION);
        assertThat(redirectUri, startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));
        assertThat(URI.create(redirectUri).getQuery(), equalTo("interrupt=CONSENT_REQUIRED"));

        assertEventTypesReceived(
                auditTopic, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    private String givenAnExistingSession(CredentialTrustLevel credentialTrustLevel)
            throws Exception {
        String sessionId = redis.createSession();
        redis.setSessionCredentialTrustLevel(sessionId, credentialTrustLevel);
        return sessionId;
    }

    private Map<String, String> constructQueryStringParameters(
            Optional<String> clientId,
            Optional<String> prompt,
            String scopes,
            Optional<String> vtr) {
        final Map<String, String> queryStringParameters = new HashMap<>();
        Nonce nonce = new Nonce();
        queryStringParameters.putAll(
                Map.of(
                        "response_type",
                        "code",
                        "redirect_uri",
                        "localhost",
                        "state",
                        "8VAVNSxHO1HwiNDhwchQKdd7eOUK3ltKfQzwPDxu9LU",
                        "nonce",
                        nonce.getValue(),
                        "client_id",
                        clientId.orElse("test-client"),
                        "scope",
                        scopes));

        prompt.ifPresent(s -> queryStringParameters.put("prompt", s));

        vtr.ifPresent(s -> queryStringParameters.put("vtr", jsonArrayOf(vtr.get())));
        return queryStringParameters;
    }

    private String getHeaderValueByParamName(Response response, String paramName) {
        return response.getHeaders().get(paramName).get(0).toString();
    }

    private String getHeaderValueByParamName(
            APIGatewayProxyResponseEvent response, String paramName) {
        return response.getHeaders().get(paramName);
    }

    private void registerUserWithConsentedScope(Optional<Scope> consentedScope) {
        userStore.signUp(TEST_EMAIL_ADDRESS, TEST_PASSWORD);
        consentedScope.ifPresent(
                scope -> {
                    Set<String> claims = ValidScopes.getClaimsForListOfScopes(scope.toStringList());
                    ClientConsent clientConsent =
                            new ClientConsent(
                                    CLIENT_ID,
                                    claims,
                                    LocalDateTime.now(ZoneId.of("UTC")).toString());
                    userStore.updateConsent(TEST_EMAIL_ADDRESS, clientConsent);
                });
    }

    private void registerClient(String clientId, String clientName, List<String> scopes) {
        clientStore.registerClient(
                clientId,
                clientName,
                singletonList("localhost"),
                singletonList("joe.bloggs@digital.cabinet-office.gov.uk"),
                scopes,
                Base64.getMimeEncoder().encodeToString(KEY_PAIR.getPublic().getEncoded()),
                singletonList("http://localhost/post-redirect-logout"),
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public",
                true);
    }
}
