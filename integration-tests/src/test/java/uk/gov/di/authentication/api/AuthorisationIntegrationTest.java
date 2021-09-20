package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCError;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.Response;
import org.glassfish.jersey.client.ClientProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.KeyPairHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.authentication.oidc.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.AuthenticationValues;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.security.KeyPair;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static com.nimbusds.openid.connect.sdk.Prompt.Type.LOGIN;
import static com.nimbusds.openid.connect.sdk.Prompt.Type.NONE;
import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class AuthorisationIntegrationTest extends IntegrationTestEndpoints {

    private static final String AUTHORIZE_ENDPOINT = "/authorize";

    private static final String CLIENT_ID = "test-client";
    private static final String AM_CLIENT_ID = "am-test-client";
    private static final String INVALID_CLIENT_ID = "invalid-test-client";
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
                        Optional.of(CLIENT_ID), Optional.empty(), Optional.empty(), "openid");

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
        String sessionId = givenAnExistingSession(SessionState.AUTHENTICATION_REQUIRED);

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
        String sessionId = givenAnExistingSession(SessionState.AUTHENTICATED);

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
        String sessionId = givenAnExistingSession(SessionState.AUTHENTICATED);

        Response response =
                doAuthorisationRequest(
                        Optional.of(CLIENT_ID),
                        Optional.of(new Cookie("gs", format("%s.456", sessionId))),
                        Optional.of(NONE.toString()),
                        "openid");

        assertEquals(302, response.getStatus());
        assertNotNull(response.getCookies().get("gs"));
        assertThat(response.getCookies().get("gs").getValue(), not(startsWith(sessionId)));
        assertThat(
                getHeaderValueByParamName(response, ResponseHeaders.LOCATION),
                startsWith(configurationService.getAuthCodeURI().toString()));
    }

    @Test
    public void shouldPromptForLoginWhenPromptLoginAndUserAuthenticated() throws Exception {
        String sessionId = givenAnExistingSession(SessionState.AUTHENTICATED);

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
        /*
           TODO:
               In this scenario the session state would be set to AUTHENTICATION_REQUIRED.
               At present there is no way to retrieve the state in an integration test.
               A further assertion should be added when possible.
        */
    }

    private String givenAnExistingSession(SessionState initialState) throws Exception {
        String sessionId = RedisHelper.createSession();
        RedisHelper.setSessionState(sessionId, initialState);
        return sessionId;
    }

    private Response doAuthorisationRequest(
            Optional<String> clientId,
            Optional<Cookie> cookie,
            Optional<String> prompt,
            String scopes) {
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
        Invocation.Builder builder = webTarget.request();
        cookie.ifPresent(builder::cookie);
        return builder.get();
    }

    private String getHeaderValueByParamName(Response response, String paramName) {
        return response.getHeaders().get(paramName).get(0).toString();
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
                "public",
                AuthenticationValues.VERY_HIGH_LEVEL.getValue());
    }
}
