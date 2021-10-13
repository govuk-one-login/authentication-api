package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCError;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.Response;
import net.minidev.json.JSONArray;
import org.glassfish.jersey.client.ClientProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.KeyPairHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.authentication.oidc.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.net.URI;
import java.security.KeyPair;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static com.nimbusds.openid.connect.sdk.Prompt.Type.LOGIN;
import static com.nimbusds.openid.connect.sdk.Prompt.Type.NONE;
import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;
import static uk.gov.di.authentication.shared.entity.SessionState.AUTHENTICATED;
import static uk.gov.di.authentication.shared.entity.SessionState.AUTHENTICATION_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.CONSENT_REQUIRED;
import static uk.gov.di.authentication.shared.entity.SessionState.UPLIFT_REQUIRED_CM;

public class AuthorisationIntegrationTest extends IntegrationTestEndpoints {

    private static final String AUTHORIZE_ENDPOINT = "/authorize";

    private static final String CLIENT_ID = "test-client";
    private static final String AM_CLIENT_ID = "am-test-client";
    private static final String INVALID_CLIENT_ID = "invalid-test-client";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_PASSWORD = "password";
    private static final KeyPair KEY_PAIR = KeyPairHelper.GENERATE_RSA_KEY_PAIR();

    private static final ConfigurationService configurationService = new ConfigurationService();

    @BeforeEach
    public void setup() {
        registerClient(CLIENT_ID, "test-client", singletonList("openid"));
    }

    @Test
    public void shouldReturnUnmetAuthenticationRequirementsErrorWhenUsingInvalidClient() {
        Response response =
                doAuthorisationRequest(
                        Optional.of(INVALID_CLIENT_ID),
                        Optional.empty(),
                        Optional.empty(),
                        "openid");
        assertEquals(302, response.getStatus());
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                containsString(OAuth2Error.UNAUTHORIZED_CLIENT.getCode()));
    }

    @Test
    public void shouldRedirectToLoginWhenNoCookie() {
        Response response =
                doAuthorisationRequest(
                        Optional.of(CLIENT_ID),
                        Optional.empty(),
                        Optional.empty(),
                        "openid",
                        Optional.of("Cl.Cm"));

        assertEquals(302, response.getStatus());
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                startsWith(configurationService.getLoginURI().toString()));
        assertNotNull(response.getCookies().get("gs"));
    }

    @Test
    public void shouldRedirectToLoginForAccountManagementClient() {
        registerClient(AM_CLIENT_ID, "am-client-name", List.of("openid", "am"));
        Response response =
                doAuthorisationRequest(
                        Optional.of(AM_CLIENT_ID), Optional.empty(), Optional.empty(), "openid am");

        assertEquals(302, response.getStatus());
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                startsWith(configurationService.getLoginURI().toString()));
        assertNotNull(response.getCookies().get("gs"));
    }

    @Test
    public void shouldReturnInvalidScopeErrorWhenNotAccountManagementClient() {
        Response response =
                doAuthorisationRequest(
                        Optional.of(CLIENT_ID), Optional.empty(), Optional.empty(), "openid am");
        assertEquals(302, response.getStatus());
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                containsString(
                        "error=invalid_scope&error_description=Invalid%2C+unknown+or+malformed+scope"));
    }

    @Test
    public void shouldRedirectToLoginWhenBadCookie() {
        Response response =
                doAuthorisationRequest(
                        Optional.of(CLIENT_ID),
                        Optional.of(new Cookie("gs", "this is bad")),
                        Optional.empty(),
                        "openid");

        assertEquals(302, response.getStatus());
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                startsWith(configurationService.getLoginURI().toString()));
        assertNotNull(response.getCookies().get("gs"));
    }

    @Test
    public void shouldRedirectToLoginWhenCookieHasUnknownSessionId() {
        Response response =
                doAuthorisationRequest(
                        Optional.of(CLIENT_ID),
                        Optional.of(new Cookie("gs", "123.456")),
                        Optional.empty(),
                        "openid");

        assertEquals(302, response.getStatus());
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                startsWith(configurationService.getLoginURI().toString()));
        assertNotNull(response.getCookies().get("gs"));
    }

    @Test
    public void shouldRedirectToLoginWhenSessionFromCookieIsNotAuthenticated() throws Exception {
        String sessionId = givenAnExistingSession(AUTHENTICATION_REQUIRED);
        RedisHelper.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        registerUserWithConsentedScope(Optional.empty());

        Response response =
                doAuthorisationRequest(
                        Optional.of(CLIENT_ID),
                        Optional.of(new Cookie("gs", format("%s.456", sessionId))),
                        Optional.empty(),
                        "openid");

        assertEquals(302, response.getStatus());
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                startsWith(configurationService.getLoginURI().toString()));
        assertNotNull(response.getCookies().get("gs"));
        assertThat(response.getCookies().get("gs").getValue(), not(startsWith(sessionId)));
    }

    @Test
    public void shouldIssueAuthorisationCodeWhenSessionFromCookieIsAuthenticated()
            throws Exception {
        String sessionId = givenAnExistingSession(AUTHENTICATED);
        RedisHelper.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        registerUserWithConsentedScope(Optional.of(new Scope(OIDCScopeValue.OPENID)));

        Response response =
                doAuthorisationRequest(
                        Optional.of(CLIENT_ID),
                        Optional.of(new Cookie("gs", format("%s.456", sessionId))),
                        Optional.empty(),
                        "openid");

        assertEquals(302, response.getStatus());
        // TODO: Update assertions to reflect code issuance, once we've written that code
        assertNotNull(response.getCookies().get("gs"));
        assertThat(response.getCookies().get("gs").getValue(), not(startsWith(sessionId)));
    }

    @Test
    public void shouldReturnLoginRequiredErrorWhenPromptNoneAndUserUnauthenticated() {
        Response response =
                doAuthorisationRequest(
                        Optional.of(CLIENT_ID),
                        Optional.empty(),
                        Optional.of(NONE.toString()),
                        "openid");
        assertEquals(302, response.getStatus());
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                containsString(OIDCError.LOGIN_REQUIRED_CODE));
    }

    @Test
    public void shouldNotPromptForLoginWhenPromptNoneAndUserAuthenticated() throws Exception {
        String sessionId = givenAnExistingSession(AUTHENTICATED);
        RedisHelper.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        registerUserWithConsentedScope(Optional.of(new Scope(OIDCScopeValue.OPENID)));

        Response response =
                doAuthorisationRequest(
                        Optional.of(CLIENT_ID),
                        Optional.of(new Cookie("gs", format("%s.456", sessionId))),
                        Optional.of(NONE.toString()),
                        OIDCScopeValue.OPENID.getValue());

        assertEquals(302, response.getStatus());
        assertNotNull(response.getCookies().get("gs"));
        assertThat(response.getCookies().get("gs").getValue(), not(startsWith(sessionId)));
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                startsWith(configurationService.getLoginURI().toString()));
    }

    @Test
    public void shouldPromptForLoginWhenPromptLoginAndUserAuthenticated() throws Exception {
        String sessionId = givenAnExistingSession(AUTHENTICATED);
        RedisHelper.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        registerUserWithConsentedScope(Optional.empty());

        Response response =
                doAuthorisationRequest(
                        Optional.of(CLIENT_ID),
                        Optional.of(new Cookie("gs", format("%s.456", sessionId))),
                        Optional.of(LOGIN.toString()),
                        "openid");

        assertEquals(302, response.getStatus());
        assertNotNull(response.getCookies().get("gs"));
        assertThat(response.getCookies().get("gs").getValue(), not(startsWith(sessionId)));
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                startsWith(configurationService.getLoginURI().toString()));
        String newSessionId = response.getCookies().get("gs").getValue().split("\\.")[0];
        assertThat(
                RedisHelper.getSession(newSessionId).getState(), equalTo(AUTHENTICATION_REQUIRED));
    }

    @Test
    public void shouldRequireUpliftWhenHighCredentialLevelOfTrustRequested() throws Exception {
        String sessionId = givenAnExistingSession(AUTHENTICATED, LOW_LEVEL);
        RedisHelper.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        registerUserWithConsentedScope(Optional.empty());

        Response response =
                doAuthorisationRequest(
                        Optional.of(CLIENT_ID),
                        Optional.of(new Cookie("gs", format("%s.456", sessionId))),
                        Optional.empty(),
                        "openid");

        assertEquals(302, response.getStatus());
        assertNotNull(response.getCookies().get("gs"));
        assertThat(response.getCookies().get("gs").getValue(), not(startsWith(sessionId)));
        String redirectUri = getHeaderValueByParamName(response, ResponseHeaders.LOCATION);
        assertThat(redirectUri, startsWith(configurationService.getLoginURI().toString()));
        assertThat(URI.create(redirectUri).getQuery(), equalTo("interrupt=UPLIFT_REQUIRED_CM"));
        String newSessionId = response.getCookies().get("gs").getValue().split("\\.")[0];
        assertThat(RedisHelper.getSession(newSessionId).getState(), equalTo(UPLIFT_REQUIRED_CM));
    }

    @Test
    public void shouldRequireConsentWhenUserAuthenticatedAndConsentIsNotGiven() throws Exception {
        String sessionId = givenAnExistingSession(AUTHENTICATED);
        RedisHelper.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        registerUserWithConsentedScope(Optional.empty());

        Response response =
                doAuthorisationRequest(
                        Optional.of(CLIENT_ID),
                        Optional.of(new Cookie("gs", format("%s.456", sessionId))),
                        Optional.of(NONE.toString()),
                        OIDCScopeValue.OPENID.getValue());

        assertEquals(302, response.getStatus());
        assertNotNull(response.getCookies().get("gs"));
        assertThat(response.getCookies().get("gs").getValue(), not(startsWith(sessionId)));
        String redirectUri = getHeaderValueByParamName(response, ResponseHeaders.LOCATION);
        assertThat(redirectUri, startsWith(configurationService.getLoginURI().toString()));
        assertThat(URI.create(redirectUri).getQuery(), equalTo("interrupt=CONSENT_REQUIRED"));
        String newSessionId = response.getCookies().get("gs").getValue().split("\\.")[0];
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

    private Response doAuthorisationRequest(
            Optional<String> clientId,
            Optional<Cookie> cookie,
            Optional<String> prompt,
            String scopes) {
        return doAuthorisationRequest(clientId, cookie, prompt, scopes, Optional.empty());
    }

    private Response doAuthorisationRequest(
            Optional<String> clientId,
            Optional<Cookie> cookie,
            Optional<String> prompt,
            String scopes,
            Optional<String> vtr) {
        Client client = ClientBuilder.newClient();
        Nonce nonce = new Nonce();
        WebTarget webTarget =
                client.target(ROOT_RESOURCE_URL + AUTHORIZE_ENDPOINT)
                        .queryParam("response_type", "code")
                        .queryParam("redirect_uri", "localhost")
                        .queryParam("state", "8VAVNSxHO1HwiNDhwchQKdd7eOUK3ltKfQzwPDxu9LU")
                        .queryParam("nonce", nonce.getValue())
                        .queryParam("client_id", clientId.orElse("test-client"))
                        .queryParam("scope", scopes)
                        .property(ClientProperties.FOLLOW_REDIRECTS, Boolean.FALSE);
        if (prompt.isPresent()) {
            webTarget = webTarget.queryParam("prompt", prompt.get());
        }
        if (vtr.isPresent()) {
            JSONArray jsonArray = new JSONArray();
            jsonArray.add(vtr.get());
            webTarget = webTarget.queryParam("vtr", jsonArray.toJSONString());
        }
        Invocation.Builder builder = webTarget.request();
        cookie.ifPresent(builder::cookie);
        return builder.get();
    }

    private String getHeaderValueByParamName(Response response, String paramName) {
        return response.getHeaders().get(paramName).get(0).toString();
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
