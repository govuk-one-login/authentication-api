package uk.gov.di.authentication.api;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCError;
import jakarta.ws.rs.core.Response;
import net.minidev.json.JSONArray;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.entity.ResponseHeaders;
import uk.gov.di.authentication.oidc.lambda.AuthorisationHandler;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.sharedtest.helper.DynamoHelper;
import uk.gov.di.authentication.sharedtest.helper.KeyPairHelper;
import uk.gov.di.authentication.sharedtest.helper.RedisHelper;

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
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;
import static uk.gov.di.authentication.shared.entity.SessionState.AUTHENTICATED;
import static uk.gov.di.authentication.shared.entity.SessionState.AUTHENTICATION_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.CONSENT_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.UPLIFT_REQUIRED_CM;
import static uk.gov.di.authentication.shared.helpers.CookieHelper.getHttpCookieFromResponseHeaders;
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
        handler = new AuthorisationHandler(configurationService);
    }

    @Test
    void shouldReturnUnmetAuthenticationRequirementsErrorWhenUsingInvalidClient() {
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
                startsWith(configurationService.getLoginURI().toString()));
        assertThat(
                getHttpCookieFromResponseHeaders(response.getHeaders(), "gs").isPresent(),
                equalTo(true));
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
                startsWith(configurationService.getLoginURI().toString()));
        assertThat(
                getHttpCookieFromResponseHeaders(response.getHeaders(), "gs").isPresent(),
                equalTo(true));
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
                startsWith(configurationService.getLoginURI().toString()));
        assertThat(
                getHttpCookieFromResponseHeaders(response.getHeaders(), "gs").isPresent(),
                equalTo(true));
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
                startsWith(configurationService.getLoginURI().toString()));
        assertThat(
                getHttpCookieFromResponseHeaders(response.getHeaders(), "gs").isPresent(),
                equalTo(true));
    }

    @Test
    void shouldRedirectToLoginWhenSessionFromCookieIsNotAuthenticated() throws Exception {
        String sessionId = givenAnExistingSession(AUTHENTICATION_REQUIRED);
        RedisHelper.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
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
                startsWith(configurationService.getLoginURI().toString()));

        var cookie = getHttpCookieFromResponseHeaders(response.getHeaders(), "gs");
        assertThat(cookie.isPresent(), equalTo(true));
        assertThat(cookie.get().getValue(), not(startsWith(sessionId)));
    }

    @Test
    void shouldIssueAuthorisationCodeWhenSessionFromCookieIsAuthenticated() throws Exception {
        String sessionId = givenAnExistingSession(AUTHENTICATED);
        RedisHelper.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
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
        var cookie = getHttpCookieFromResponseHeaders(response.getHeaders(), "gs");
        assertThat(cookie.isPresent(), equalTo(true));
        assertThat(cookie.get().getValue(), not(startsWith(sessionId)));
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
    }

    @Test
    void shouldNotPromptForLoginWhenPromptNoneAndUserAuthenticated() throws Exception {
        String sessionId = givenAnExistingSession(AUTHENTICATED);
        RedisHelper.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
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
        var cookie = getHttpCookieFromResponseHeaders(response.getHeaders(), "gs");
        assertThat(cookie.isPresent(), equalTo(true));
        assertThat(cookie.get().getValue(), not(startsWith(sessionId)));
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                startsWith(configurationService.getLoginURI().toString()));
    }

    @Test
    void shouldPromptForLoginWhenPromptLoginAndUserAuthenticated() throws Exception {
        String sessionId = givenAnExistingSession(AUTHENTICATED);
        RedisHelper.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
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
        var cookie = getHttpCookieFromResponseHeaders(response.getHeaders(), "gs");
        assertThat(cookie.isPresent(), equalTo(true));
        assertThat(cookie.get().getValue(), not(startsWith(sessionId)));
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                startsWith(configurationService.getLoginURI().toString()));
        String newSessionId = cookie.get().getValue().split("\\.")[0];
        assertThat(
                RedisHelper.getSession(newSessionId).getState(), equalTo(AUTHENTICATION_REQUIRED));
    }

    @Test
    void shouldRequireUpliftWhenHighCredentialLevelOfTrustRequested() throws Exception {
        String sessionId = givenAnExistingSession(AUTHENTICATED, LOW_LEVEL);
        RedisHelper.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
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

        var cookie = getHttpCookieFromResponseHeaders(response.getHeaders(), "gs");
        assertThat(cookie.isPresent(), equalTo(true));
        assertThat(cookie.get().getValue(), not(startsWith(sessionId)));

        String redirectUri = getHeaderValueByParamName(response, ResponseHeaders.LOCATION);
        assertThat(redirectUri, startsWith(configurationService.getLoginURI().toString()));
        assertThat(URI.create(redirectUri).getQuery(), equalTo("interrupt=UPLIFT_REQUIRED_CM"));

        String newSessionId = cookie.get().getValue().split("\\.")[0];
        assertThat(RedisHelper.getSession(newSessionId).getState(), equalTo(UPLIFT_REQUIRED_CM));
    }

    @Test
    void shouldRequireConsentWhenUserAuthenticatedAndConsentIsNotGiven() throws Exception {
        String sessionId = givenAnExistingSession(AUTHENTICATED);
        RedisHelper.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
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

        var cookie = getHttpCookieFromResponseHeaders(response.getHeaders(), "gs");
        assertThat(cookie.isPresent(), equalTo(true));
        assertThat(cookie.get().getValue(), not(startsWith(sessionId)));

        String redirectUri = getHeaderValueByParamName(response, ResponseHeaders.LOCATION);
        assertThat(redirectUri, startsWith(configurationService.getLoginURI().toString()));
        assertThat(URI.create(redirectUri).getQuery(), equalTo("interrupt=CONSENT_REQUIRED"));

        String newSessionId = cookie.get().getValue().split("\\.")[0];
        assertThat(RedisHelper.getSession(newSessionId).getState(), equalTo(CONSENT_REQUIRED));
    }

    private String givenAnExistingSession(SessionState initialState) throws Exception {
        return givenAnExistingSession(initialState, MEDIUM_LEVEL);
    }

    private String givenAnExistingSession(
            SessionState initialState, CredentialTrustLevel credentialTrustLevel) throws Exception {
        String sessionId = RedisHelper.createSession();
        RedisHelper.setSessionState(sessionId, initialState, credentialTrustLevel);
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

        vtr.ifPresent(
                s -> {
                    JSONArray jsonArray = new JSONArray();
                    jsonArray.add(vtr.get());
                    queryStringParameters.put("vtr", jsonArray.toJSONString());
                });
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
        DynamoHelper.signUp(TEST_EMAIL_ADDRESS, TEST_PASSWORD);
        consentedScope.ifPresent(
                scope -> {
                    Set<String> claims = ValidScopes.getClaimsForListOfScopes(scope.toStringList());
                    ClientConsent clientConsent =
                            new ClientConsent(
                                    CLIENT_ID,
                                    claims,
                                    LocalDateTime.now(ZoneId.of("UTC")).toString());
                    DynamoHelper.updateConsent(TEST_EMAIL_ADDRESS, clientConsent);
                });
    }

    private void registerClient(String clientId, String clientName, List<String> scopes) {
        DynamoHelper.registerClient(
                clientId,
                clientName,
                singletonList("localhost"),
                singletonList("joe.bloggs@digital.cabinet-office.gov.uk"),
                scopes,
                Base64.getMimeEncoder().encodeToString(KEY_PAIR.getPublic().getEncoded()),
                singletonList("http://localhost/post-redirect-logout"),
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public");
    }
}
