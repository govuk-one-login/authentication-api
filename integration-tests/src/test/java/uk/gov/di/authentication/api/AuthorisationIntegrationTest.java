package uk.gov.di.authentication.api;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.authentication.oidc.lambda.AuthorisationHandler;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.helpers.CookieHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.DocAppJwksExtension;
import uk.gov.di.authentication.sharedtest.helper.KeyPairHelper;

import java.net.HttpCookie;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static com.nimbusds.openid.connect.sdk.OIDCScopeValue.OPENID;
import static com.nimbusds.openid.connect.sdk.Prompt.Type.LOGIN;
import static com.nimbusds.openid.connect.sdk.Prompt.Type.NONE;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.app.domain.DocAppAuditableEvent.DOC_APP_AUTHORISATION_REQUESTED;
import static uk.gov.di.authentication.oidc.domain.OidcAuditableEvent.AUTHORISATION_INITIATED;
import static uk.gov.di.authentication.oidc.domain.OidcAuditableEvent.AUTHORISATION_REQUEST_ERROR;
import static uk.gov.di.authentication.oidc.domain.OidcAuditableEvent.AUTHORISATION_REQUEST_RECEIVED;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;
import static uk.gov.di.authentication.shared.helpers.CookieHelper.getHttpCookieFromMultiValueResponseHeaders;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper.jsonArrayOf;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthorisationIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String CLIENT_ID = "test-client";
    private static final String RP_REDIRECT_URI = "https://rp-uri/redirect";
    private static final String AM_CLIENT_ID = "am-test-client";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_PASSWORD = "password";
    private static final KeyPair KEY_PAIR = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
    public static final String DUMMY_CLIENT_SESSION_ID = "456";

    @RegisterExtension
    public static final DocAppJwksExtension jwksExtension = new DocAppJwksExtension();

    private final KeyPair keyPair = generateRsaKeyPair();
    private static final String ENCRYPTION_KEY_ID = UUID.randomUUID().toString();

    private static final URI CALLBACK_URI = URI.create("http://localhost/callback");
    private static final URI AUTHORIZE_URI = URI.create("http://doc-app/authorize");
    private static final String DOC_APP_CLIENT_ID = "doc-app-client-id";

    private static IntegrationTestConfigurationService configuration =
            configWithDocAppDecouple(false);

    @Test
    void shouldRedirectToLoginUriWhenNoCookieIsPresent() {
        setupForAuthJourney();
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(Optional.empty()),
                        constructQueryStringParameters(CLIENT_ID, null, "openid", "Cl.Cm"),
                        Optional.of("GET"));
        assertThat(response, hasStatus(302));
        assertThat(
                getLocationResponseHeader(response),
                startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));
        assertThat(
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs")
                        .isPresent(),
                equalTo(true));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldRedirectToLoginUriWhenNoCookieIsPresentButIdentityVectorsArePresent() {
        setupForAuthJourney();
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(Optional.empty()),
                        constructQueryStringParameters(CLIENT_ID, null, "openid", "P2.Cl.Cm"),
                        Optional.of("GET"));
        assertThat(response, hasStatus(302));

        String redirectUri = getLocationResponseHeader(response);
        assertThat(redirectUri, startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));
        assertThat(
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs")
                        .isPresent(),
                equalTo(true));
        assertThat(URI.create(redirectUri).getQuery(), equalTo(null));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldRedirectToLoginWithSamePersistentCookieValueInRequest() {
        setupForAuthJourney();
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(
                                        new HttpCookie(
                                                "di-persistent-session-id",
                                                "persistent-id-value"))),
                        constructQueryStringParameters(CLIENT_ID, null, "openid", "Cl.Cm"),
                        Optional.of("GET"));

        assertThat(response, hasStatus(302));
        String redirectUri = getLocationResponseHeader(response);
        assertThat(redirectUri, startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));
        assertThat(URI.create(redirectUri).getQuery(), equalTo(null));
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
        assertThat(persistentCookie.get().getValue(), containsString("persistent-id-value--"));
        assertTrue(
                CookieHelper.isValidCookieWithDoubleDashedTimestamp(
                        persistentCookie.get().getValue()));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldRedirectToLoginWithLanguageCookieSetWhenUILocalesPopulated() {
        setupForAuthJourney();
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(
                                        new HttpCookie(
                                                "di-persistent-session-id",
                                                "persistent-id-value"))),
                        constructQueryStringParameters(CLIENT_ID, null, "openid", "Cl.Cm", "en"),
                        Optional.of("GET"));

        assertThat(response, hasStatus(302));
        String redirectUri = getLocationResponseHeader(response);
        assertThat(redirectUri, startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));
        assertThat(URI.create(redirectUri).getQuery(), equalTo(null));
        assertThat(
                response.getMultiValueHeaders().get(ResponseHeaders.SET_COOKIE).size(), equalTo(3));
        assertThat(
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs")
                        .isPresent(),
                equalTo(true));
        var persistentCookie =
                getHttpCookieFromMultiValueResponseHeaders(
                        response.getMultiValueHeaders(), "di-persistent-session-id");
        assertThat(persistentCookie.isPresent(), equalTo(true));
        assertThat(persistentCookie.get().getValue(), containsString("persistent-id-value--"));
        assertTrue(
                CookieHelper.isValidCookieWithDoubleDashedTimestamp(
                        persistentCookie.get().getValue()));
        var languageCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "lng");
        assertThat(languageCookie.isPresent(), equalTo(true));
        assertThat(languageCookie.get().getValue(), equalTo("en"));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldRedirectToLoginUriForAccountManagementClient() {
        setupForAuthJourney();
        registerClient(AM_CLIENT_ID, "am-client-name", List.of("openid", "am"), ClientType.WEB);
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(Optional.empty()),
                        constructQueryStringParameters(AM_CLIENT_ID, null, "openid am", null),
                        Optional.of("GET"));

        assertThat(response, hasStatus(302));
        String redirectUri = getLocationResponseHeader(response);
        assertThat(URI.create(redirectUri).getQuery(), equalTo(null));
        assertThat(redirectUri, startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));
        assertThat(
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs")
                        .isPresent(),
                equalTo(true));
        assertThat(
                getHttpCookieFromMultiValueResponseHeaders(
                                response.getMultiValueHeaders(), "di-persistent-session-id")
                        .isPresent(),
                equalTo(true));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldReturnInvalidScopeErrorToRPWhenNotAccountManagementClient() {
        setupForAuthJourney();
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(Optional.empty()),
                        constructQueryStringParameters(CLIENT_ID, null, "openid am", null),
                        Optional.of("GET"));

        assertThat(response, hasStatus(302));
        String redirectUri = getLocationResponseHeader(response);
        assertThat(redirectUri, containsString(OAuth2Error.INVALID_SCOPE.getCode()));
        assertThat(redirectUri, startsWith(RP_REDIRECT_URI));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_REQUEST_ERROR));
    }

    @Test
    void shouldRedirectToLoginUriWhenBadCookieIsPresent() {
        setupForAuthJourney();
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(Optional.of(new HttpCookie("gs", "this is bad"))),
                        constructQueryStringParameters(CLIENT_ID, null, "openid", null),
                        Optional.of("GET"));

        assertThat(response, hasStatus(302));
        String redirectUri = getLocationResponseHeader(response);
        assertThat(URI.create(redirectUri).getQuery(), equalTo(null));
        assertThat(redirectUri, startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));
        assertThat(
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs")
                        .isPresent(),
                equalTo(true));
        assertThat(
                getHttpCookieFromMultiValueResponseHeaders(
                                response.getMultiValueHeaders(), "di-persistent-session-id")
                        .isPresent(),
                equalTo(true));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldRedirectToLoginUriWhenCookieHasUnknownSessionId() {
        setupForAuthJourney();
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(buildSessionCookie("123", DUMMY_CLIENT_SESSION_ID))),
                        constructQueryStringParameters(CLIENT_ID, null, "openid", null),
                        Optional.of("GET"));

        assertThat(response, hasStatus(302));
        String redirectUri = getLocationResponseHeader(response);
        assertThat(URI.create(redirectUri).getQuery(), equalTo(null));
        assertThat(redirectUri, startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));
        assertThat(
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs")
                        .isPresent(),
                equalTo(true));
        assertThat(
                getHttpCookieFromMultiValueResponseHeaders(
                                response.getMultiValueHeaders(), "di-persistent-session-id")
                        .isPresent(),
                equalTo(true));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldRedirectToLoginUriWhenUserHasPreviousSessionButHasNotConsented() throws Exception {
        setupForAuthJourney();
        String sessionId = givenAnExistingSession(MEDIUM_LEVEL);
        redis.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        registerUser();

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(
                                        buildSessionCookie(sessionId, DUMMY_CLIENT_SESSION_ID))),
                        constructQueryStringParameters(CLIENT_ID, null, "openid", null),
                        Optional.of("GET"));

        assertThat(response, hasStatus(302));
        String redirectUri = getLocationResponseHeader(response);
        assertThat(redirectUri, startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));
        var cookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs");
        assertThat(
                getHttpCookieFromMultiValueResponseHeaders(
                                response.getMultiValueHeaders(), "di-persistent-session-id")
                        .isPresent(),
                equalTo(true));
        assertThat(cookie.isPresent(), equalTo(true));
        assertThat(cookie.get().getValue(), not(startsWith(sessionId)));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldRedirectToLoginUriWhenUserHasPreviousSessionButHasConsented() throws Exception {
        setupForAuthJourney();
        String sessionId = givenAnExistingSession(MEDIUM_LEVEL);
        redis.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        registerUserWithConsentedScope(new Scope(OPENID));

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(
                                        buildSessionCookie(sessionId, DUMMY_CLIENT_SESSION_ID))),
                        constructQueryStringParameters(CLIENT_ID, null, "openid", null),
                        Optional.of("GET"));

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

        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldRedirectToLoginUriWhenUserHasPreviousSessionButRequiresIdentity() throws Exception {
        setupForAuthJourney();
        String sessionId = givenAnExistingSession(MEDIUM_LEVEL);
        redis.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        registerUserWithConsentedScope(new Scope(OPENID));

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(
                                        buildSessionCookie(sessionId, DUMMY_CLIENT_SESSION_ID))),
                        constructQueryStringParameters(CLIENT_ID, null, "openid", "P2.Cl.Cm"),
                        Optional.of("GET"));

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

        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldRedirectToFrontendWhenPromptNoneAndUserUnauthenticated() {
        setupForAuthJourney();
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(Optional.empty()),
                        constructQueryStringParameters(CLIENT_ID, NONE.toString(), "openid", null),
                        Optional.of("GET"));
        assertThat(response, hasStatus(302));

        String redirectUri = getLocationResponseHeader(response);
        assertThat(redirectUri, startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));
        assertThat(URI.create(redirectUri).getQuery(), equalTo(null));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldNotPromptForLoginWhenPromptNoneAndUserAuthenticated() throws Exception {
        setupForAuthJourney();
        String sessionId = givenAnExistingSession(MEDIUM_LEVEL);
        redis.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        registerUserWithConsentedScope(new Scope(OPENID));

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(
                                        buildSessionCookie(sessionId, DUMMY_CLIENT_SESSION_ID))),
                        constructQueryStringParameters(
                                CLIENT_ID, NONE.toString(), OPENID.getValue(), null),
                        Optional.of("GET"));

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
                getLocationResponseHeader(response),
                startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldPromptForLoginWhenPromptLoginAndUserAuthenticated() throws Exception {
        setupForAuthJourney();
        String sessionId = givenAnExistingSession(MEDIUM_LEVEL);
        redis.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        registerUser();

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(
                                        buildSessionCookie(sessionId, DUMMY_CLIENT_SESSION_ID))),
                        constructQueryStringParameters(
                                CLIENT_ID, LOGIN.toString(), OPENID.getValue(), null),
                        Optional.of("GET"));

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

        String redirectUri = getLocationResponseHeader(response);
        assertThat(redirectUri, startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));
        assertThat(URI.create(redirectUri).getQuery(), equalTo("prompt=login"));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldRequireUpliftWhenHighCredentialLevelOfTrustRequested() throws Exception {
        setupForAuthJourney();
        String sessionId = givenAnExistingSession(LOW_LEVEL);
        redis.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        registerUserWithConsentedScope(new Scope(OPENID));

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(
                                        buildSessionCookie(sessionId, DUMMY_CLIENT_SESSION_ID))),
                        constructQueryStringParameters(
                                CLIENT_ID, null, OPENID.getValue(), MEDIUM_LEVEL.getValue()),
                        Optional.of("GET"));

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

        String redirectUri = getLocationResponseHeader(response);
        assertThat(redirectUri, startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldRequireConsentWhenUserAuthenticatedAndConsentIsNotGiven() throws Exception {
        setupForAuthJourney();
        String sessionId = givenAnExistingSession(MEDIUM_LEVEL);
        redis.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        registerUser();

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(
                                        buildSessionCookie(sessionId, DUMMY_CLIENT_SESSION_ID))),
                        constructQueryStringParameters(
                                CLIENT_ID, NONE.toString(), OPENID.getValue(), null),
                        Optional.of("GET"));

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

        String redirectUri = getLocationResponseHeader(response);
        assertThat(redirectUri, startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "en", "cy", "en cy", "es fr ja", "cy-AR"})
    void shouldCallAuthorizeAsDocAppClient(String uiLocales) throws JOSEException, ParseException {
        registerClient(
                CLIENT_ID,
                "test-client",
                List.of(OPENID.getValue(), CustomScopeValue.DOC_CHECKING_APP.getValue()),
                ClientType.APP);
        handler = new AuthorisationHandler(configuration);
        txmaAuditQueue.clear();
        var signedJWT = createSignedJWT(uiLocales);
        var queryStringParameters =
                new HashMap<>(
                        Map.of(
                                "response_type",
                                "code",
                                "client_id",
                                CLIENT_ID,
                                "scope",
                                "openid",
                                "request",
                                signedJWT.serialize()));
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(Optional.empty()),
                        queryStringParameters,
                        Optional.of("GET"));
        assertThat(response, hasStatus(302));
        assertThat(
                getLocationResponseHeader(response),
                startsWith(TEST_CONFIGURATION_SERVICE.getLoginURI().toString()));
        assertThat(
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs")
                        .isPresent(),
                equalTo(true));
        var sessionCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs")
                        .orElseThrow();
        var languageCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "lng");
        if (uiLocales.contains("en")) {
            assertThat(languageCookie.isPresent(), equalTo(true));
            assertThat(languageCookie.get().getValue(), equalTo("en"));
        } else if (uiLocales.contains("cy")) {
            assertThat(languageCookie.isPresent(), equalTo(true));
            assertThat(languageCookie.get().getValue(), equalTo("cy"));
        } else {
            assertThat(languageCookie.isPresent(), equalTo(false));
        }
        var clientSessionID = sessionCookie.getValue().split("\\.")[1];
        var clientSession = redis.getClientSession(clientSessionID);
        var authRequest = AuthenticationRequest.parse(clientSession.getAuthRequestParams());
        assertTrue(authRequest.getScope().contains(CustomScopeValue.DOC_CHECKING_APP));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_INITIATED));
    }

    @Test
    void shouldGenerateCorrectResponseGivenAValidRequestWhenOnDocAppJourney() throws JOSEException {
        setupForDocAppJourney();
        SignedJWT signedJWT = createSignedJWT("");

        Map<String, String> requestParams =
                Map.of(
                        "client_id",
                        CLIENT_ID,
                        "response_type",
                        "code",
                        "request",
                        signedJWT.serialize(),
                        "scope",
                        "openid");

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                Optional.of(
                                        new HttpCookie(
                                                "di-persistent-session-id",
                                                "persistent-id-value"))),
                        requestParams,
                        Optional.of("GET"));

        var locationHeaderUri = URI.create(response.getHeaders().get("Location"));
        var expectedQueryStringRegex = "response_type=code&request=.*&client_id=doc-app-client-id";
        assertThat(response, hasStatus(302));
        assertThat(locationHeaderUri.getQuery(), matchesPattern(expectedQueryStringRegex));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(AUTHORISATION_REQUEST_RECEIVED, DOC_APP_AUTHORISATION_REQUESTED));
    }

    private Map<String, String> constructQueryStringParameters(
            String clientId, String prompt, String scopes, String vtr) {
        return constructQueryStringParameters(clientId, prompt, scopes, vtr, null);
    }

    private Map<String, String> constructQueryStringParameters(
            String clientId, String prompt, String scopes, String vtr, String uiLocales) {
        final Map<String, String> queryStringParameters =
                new HashMap<>(
                        Map.of(
                                "response_type",
                                "code",
                                "redirect_uri",
                                RP_REDIRECT_URI,
                                "state",
                                "8VAVNSxHO1HwiNDhwchQKdd7eOUK3ltKfQzwPDxu9LU",
                                "nonce",
                                new Nonce().getValue(),
                                "client_id",
                                clientId,
                                "scope",
                                scopes));

        Optional.ofNullable(prompt).ifPresent(s -> queryStringParameters.put("prompt", s));
        Optional.ofNullable(vtr).ifPresent(s -> queryStringParameters.put("vtr", jsonArrayOf(vtr)));
        Optional.ofNullable(uiLocales).ifPresent(s -> queryStringParameters.put("ui_locales", s));

        return queryStringParameters;
    }

    private void setupForAuthJourney() {
        registerClient(CLIENT_ID, "test-client", singletonList("openid"), ClientType.WEB);
        handler = new AuthorisationHandler(configuration);
        txmaAuditQueue.clear();
    }

    private void setupForDocAppJourney() {
        registerClient(
                CLIENT_ID, "test-client", List.of("openid", "doc-checking-app"), ClientType.APP);
        handler = new AuthorisationHandler(configWithDocAppDecouple(true));
        txmaAuditQueue.clear();

        var jwkKey =
                new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                        .keyUse(KeyUse.ENCRYPTION)
                        .keyID(ENCRYPTION_KEY_ID)
                        .build();
        jwksExtension.init(new JWKSet(jwkKey));
    }

    private String givenAnExistingSession(CredentialTrustLevel credentialTrustLevel)
            throws Exception {
        String sessionId = redis.createSession();
        redis.setSessionCredentialTrustLevel(sessionId, credentialTrustLevel);
        return sessionId;
    }

    private String getLocationResponseHeader(APIGatewayProxyResponseEvent response) {
        return response.getHeaders().get(ResponseHeaders.LOCATION);
    }

    private void registerUserWithConsentedScope(Scope scope) {
        userStore.signUp(TEST_EMAIL_ADDRESS, TEST_PASSWORD);
        Set<String> claims = ValidScopes.getClaimsForListOfScopes(scope.toStringList());
        ClientConsent clientConsent =
                new ClientConsent(
                        CLIENT_ID, claims, LocalDateTime.now(ZoneId.of("UTC")).toString());
        userStore.updateConsent(TEST_EMAIL_ADDRESS, clientConsent);
    }

    private void registerUser() {
        userStore.signUp(TEST_EMAIL_ADDRESS, TEST_PASSWORD);
    }

    private void registerClient(
            String clientId, String clientName, List<String> scopes, ClientType clientType) {
        clientStore.registerClient(
                clientId,
                clientName,
                singletonList(RP_REDIRECT_URI),
                singletonList("joe.bloggs@digital.cabinet-office.gov.uk"),
                scopes,
                Base64.getMimeEncoder().encodeToString(KEY_PAIR.getPublic().getEncoded()),
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public",
                true,
                clientType);
    }

    private SignedJWT createSignedJWT(String uiLocales) throws JOSEException {
        var jwtClaimsSetBuilder =
                new JWTClaimsSet.Builder()
                        .audience("http://localhost/authorize")
                        .claim("redirect_uri", RP_REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim(
                                "scope",
                                new Scope(OIDCScopeValue.OPENID, CustomScopeValue.DOC_CHECKING_APP)
                                        .toString())
                        .claim("nonce", new Nonce().getValue())
                        .claim("client_id", CLIENT_ID)
                        .claim("state", new State().getValue())
                        .issuer(CLIENT_ID);
        if (uiLocales != null && !uiLocales.isBlank()) {
            jwtClaimsSetBuilder.claim("ui_locales", uiLocales);
        }
        var jwsHeader = new JWSHeader(JWSAlgorithm.RS256);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSetBuilder.build());
        var signer = new RSASSASigner(KEY_PAIR.getPrivate());
        signedJWT.sign(signer);
        return signedJWT;
    }

    private static IntegrationTestConfigurationService configWithDocAppDecouple(
            boolean isDocAppDecoupleEnabled) {
        return new IntegrationTestConfigurationService(
                auditTopic,
                notificationsQueue,
                auditSigningKey,
                tokenSigner,
                ipvPrivateKeyJwtSigner,
                spotQueue,
                docAppPrivateKeyJwtSigner,
                configurationParameters) {
            @Override
            public String getTxmaAuditQueueUrl() {
                return txmaAuditQueue.getQueueUrl();
            }

            @Override
            public boolean isLanguageEnabled(LocaleHelper.SupportedLanguage supportedLanguage) {
                return supportedLanguage.equals(LocaleHelper.SupportedLanguage.EN)
                        || supportedLanguage.equals(LocaleHelper.SupportedLanguage.CY);
            }

            @Override
            public boolean isDocAppDecoupleEnabled() {
                return isDocAppDecoupleEnabled;
            }

            @Override
            public URI getDocAppJwksUri() {
                try {
                    return new URIBuilder()
                            .setHost("localhost")
                            .setPort(jwksExtension.getHttpPort())
                            .setPath("/.well-known/jwks.json")
                            .setScheme("http")
                            .build();
                } catch (URISyntaxException e) {
                    throw new RuntimeException(e);
                }
            }

            @Override
            public String getDocAppEncryptionKeyID() {
                return ENCRYPTION_KEY_ID;
            }

            @Override
            public String getDocAppAuthorisationClientId() {
                return DOC_APP_CLIENT_ID;
            }

            @Override
            public URI getDocAppAuthorisationURI() {
                return AUTHORIZE_URI;
            }

            @Override
            public URI getDocAppAuthorisationCallbackURI() {
                return CALLBACK_URI;
            }
        };
    }

    private static KeyPair generateRsaKeyPair() {
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }
}
