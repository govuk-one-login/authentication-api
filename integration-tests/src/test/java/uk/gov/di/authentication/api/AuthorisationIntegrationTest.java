package uk.gov.di.authentication.api;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
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
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.authentication.oidc.lambda.AuthorisationHandler;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.CustomScopeValue;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.ServiceType;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.orchestration.sharedtest.extensions.DocAppJwksExtension;
import uk.gov.di.orchestration.sharedtest.extensions.KmsKeyExtension;
import uk.gov.di.orchestration.sharedtest.extensions.OrchSessionExtension;
import uk.gov.di.orchestration.sharedtest.extensions.RpPublicKeyCacheExtension;
import uk.gov.di.orchestration.sharedtest.helper.KeyPairHelper;

import java.net.HttpCookie;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import static com.nimbusds.openid.connect.sdk.OIDCScopeValue.OPENID;
import static com.nimbusds.openid.connect.sdk.Prompt.Type.LOGIN;
import static com.nimbusds.openid.connect.sdk.Prompt.Type.NONE;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.app.domain.DocAppAuditableEvent.DOC_APP_AUTHORISATION_REQUESTED;
import static uk.gov.di.authentication.oidc.domain.OidcAuditableEvent.AUTHORISATION_INITIATED;
import static uk.gov.di.authentication.oidc.domain.OidcAuditableEvent.AUTHORISATION_REQUEST_ERROR;
import static uk.gov.di.authentication.oidc.domain.OidcAuditableEvent.AUTHORISATION_REQUEST_PARSED;
import static uk.gov.di.authentication.oidc.domain.OidcAuditableEvent.AUTHORISATION_REQUEST_RECEIVED;
import static uk.gov.di.orchestration.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.orchestration.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;
import static uk.gov.di.orchestration.shared.entity.ValidClaims.ADDRESS;
import static uk.gov.di.orchestration.shared.entity.ValidClaims.CORE_IDENTITY_JWT;
import static uk.gov.di.orchestration.shared.helpers.CookieHelper.getHttpCookieFromMultiValueResponseHeaders;
import static uk.gov.di.orchestration.shared.helpers.PersistentIdHelper.isValidPersistentSessionCookieWithDoubleDashedTimestamp;
import static uk.gov.di.orchestration.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.orchestration.sharedtest.helper.JsonArrayHelper.jsonArrayOf;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthorisationIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String CLIENT_ID = "test-client";
    private static final String BROWSER_SESSION_ID = "some-browser-session-id";
    private static final URI RP_REDIRECT_URI = URI.create("https://rp-uri/redirect");
    private static final String AM_CLIENT_ID = "am-test-client";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_PASSWORD = "password";
    private static final KeyPair KEY_PAIR = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
    public static final String DUMMY_CLIENT_SESSION_ID = "456";
    private static final String ARBITRARY_UNIX_TIMESTAMP = "1700558480962";
    private static final String PERSISTENT_SESSION_ID =
            IdGenerator.generate() + "--" + ARBITRARY_UNIX_TIMESTAMP;

    @RegisterExtension
    public static final DocAppJwksExtension jwksExtension = new DocAppJwksExtension();

    @RegisterExtension
    public static final KmsKeyExtension tokenSigningKey = new KmsKeyExtension("token-signing-key");

    @RegisterExtension
    public static final RpPublicKeyCacheExtension rpPublicKeyCacheExtension =
            new RpPublicKeyCacheExtension(180);

    @RegisterExtension
    public static final OrchSessionExtension orchSessionExtension = new OrchSessionExtension();

    public static final String publicKey =
            "-----BEGIN PUBLIC KEY-----\n"
                    + Base64.getMimeEncoder().encodeToString(KEY_PAIR.getPublic().getEncoded())
                    + "\n-----END PUBLIC KEY-----\n";

    private final KeyPair keyPair = generateRsaKeyPair();
    private static final String ENCRYPTION_KEY_ID = UUID.randomUUID().toString();

    private static final URI CALLBACK_URI = URI.create("http://localhost/callback");
    private static final URI AUTHORIZE_URI = URI.create("http://doc-app/authorize");
    private static final String DOC_APP_CLIENT_ID = "doc-app-client-id";
    private static final String CLAIMS =
            "{\"userinfo\":{\"https://vocab.account.gov.uk/v1/coreIdentityJWT\":{\"essential\":true},\"https://vocab.account.gov.uk/v1/address\":{\"essential\":true}}}";

    private static final IntegrationTestConfigurationService configuration =
            new IntegrationTestConfigurationService(
                    externalTokenSigner,
                    storageTokenSigner,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters) {
                @Override
                public String getTxmaAuditQueueUrl() {
                    return txmaAuditQueue.getQueueUrl();
                }

                @Override
                public URI getDocAppJwksURI() {
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

                @Override
                public String getOrchestrationToAuthenticationTokenSigningKeyAlias() {
                    return tokenSigningKey.getKeyAlias();
                }

                @Override
                public String getOrchestrationToAuthenticationEncryptionPublicKey() {
                    return publicKey;
                }
            };

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
                startsWith(TEST_CONFIGURATION_SERVICE.getAuthFrontendBaseURL().toString()));

        var sessionCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs");
        assertOnSessionCookie(sessionCookie);

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        AUTHORISATION_REQUEST_RECEIVED,
                        AUTHORISATION_REQUEST_PARSED,
                        AUTHORISATION_INITIATED));
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
        assertThat(
                redirectUri,
                startsWith(TEST_CONFIGURATION_SERVICE.getAuthFrontendBaseURL().toString()));
        var sessionCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs");
        assertOnSessionCookie(sessionCookie);
        assertTrue(
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "bsid")
                        .isPresent());

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        AUTHORISATION_REQUEST_RECEIVED,
                        AUTHORISATION_REQUEST_PARSED,
                        AUTHORISATION_INITIATED));
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
                                                PERSISTENT_SESSION_ID))),
                        constructQueryStringParameters(CLIENT_ID, null, "openid", "Cl.Cm"),
                        Optional.of("GET"));

        assertThat(response, hasStatus(302));
        String redirectUri = getLocationResponseHeader(response);
        assertThat(
                redirectUri,
                startsWith(TEST_CONFIGURATION_SERVICE.getAuthFrontendBaseURL().toString()));
        assertThat(
                response.getMultiValueHeaders().get(ResponseHeaders.SET_COOKIE).size(), equalTo(3));
        var sessionCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs");
        assertOnSessionCookie(sessionCookie);
        assertTrue(
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "bsid")
                        .isPresent());
        var persistentCookie =
                getHttpCookieFromMultiValueResponseHeaders(
                        response.getMultiValueHeaders(), "di-persistent-session-id");
        assertTrue(persistentCookie.isPresent());
        assertThat(persistentCookie.get().getValue(), containsString(PERSISTENT_SESSION_ID));
        assertTrue(
                isValidPersistentSessionCookieWithDoubleDashedTimestamp(
                        persistentCookie.get().getValue()));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        AUTHORISATION_REQUEST_RECEIVED,
                        AUTHORISATION_REQUEST_PARSED,
                        AUTHORISATION_INITIATED));
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
                                                PERSISTENT_SESSION_ID))),
                        constructQueryStringParameters(CLIENT_ID, null, "openid", "Cl.Cm", "en"),
                        Optional.of("GET"));

        assertThat(response, hasStatus(302));
        String redirectUri = getLocationResponseHeader(response);
        assertThat(
                redirectUri,
                startsWith(TEST_CONFIGURATION_SERVICE.getAuthFrontendBaseURL().toString()));
        assertThat(
                response.getMultiValueHeaders().get(ResponseHeaders.SET_COOKIE).size(), equalTo(4));
        var sessionCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs");
        assertOnSessionCookie(sessionCookie);
        assertTrue(
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "bsid")
                        .isPresent());
        var persistentCookie =
                getHttpCookieFromMultiValueResponseHeaders(
                        response.getMultiValueHeaders(), "di-persistent-session-id");
        assertTrue(persistentCookie.isPresent());
        assertThat(persistentCookie.get().getValue(), containsString(PERSISTENT_SESSION_ID));
        assertTrue(
                isValidPersistentSessionCookieWithDoubleDashedTimestamp(
                        persistentCookie.get().getValue()));
        var languageCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "lng");
        assertTrue(languageCookie.isPresent());
        assertThat(languageCookie.get().getValue(), equalTo("en"));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        AUTHORISATION_REQUEST_RECEIVED,
                        AUTHORISATION_REQUEST_PARSED,
                        AUTHORISATION_INITIATED));
    }

    @Test
    void shouldRedirectToLoginUriForAccountManagementClient() {
        setupForAuthJourney();
        registerClient(
                AM_CLIENT_ID,
                "am-client-name",
                List.of("openid", "am"),
                ClientType.WEB,
                false,
                false);
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(Optional.empty()),
                        constructQueryStringParameters(AM_CLIENT_ID, null, "openid am", null),
                        Optional.of("GET"));

        assertThat(response, hasStatus(302));
        String redirectUri = getLocationResponseHeader(response);
        assertThat(
                redirectUri,
                startsWith(TEST_CONFIGURATION_SERVICE.getAuthFrontendBaseURL().toString()));
        var sessionCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs");
        assertOnSessionCookie(sessionCookie);
        assertTrue(
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "bsid")
                        .isPresent());

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        AUTHORISATION_REQUEST_RECEIVED,
                        AUTHORISATION_REQUEST_PARSED,
                        AUTHORISATION_INITIATED));
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
        assertThat(redirectUri, startsWith(RP_REDIRECT_URI.toString()));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_REQUEST_ERROR));
    }

    @Test
    void shouldRedirectToLoginUriWhenBadSessionIdCookieIsPresent() {
        setupForAuthJourney();

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                new HttpCookie[] {
                                    new HttpCookie("gs", "this is bad"),
                                    new HttpCookie("bsid", BROWSER_SESSION_ID)
                                }),
                        constructQueryStringParameters(CLIENT_ID, null, "openid", null),
                        Optional.of("GET"));

        assertThat(response, hasStatus(302));
        String redirectUri = getLocationResponseHeader(response);
        assertThat(
                redirectUri,
                startsWith(TEST_CONFIGURATION_SERVICE.getAuthFrontendBaseURL().toString()));
        var sessionCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs");
        assertOnSessionCookie(sessionCookie);
        assertTrue(
                getHttpCookieFromMultiValueResponseHeaders(
                                response.getMultiValueHeaders(), "di-persistent-session-id")
                        .isPresent());

        Optional<HttpCookie> browserSessionIdCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "bsid");
        assertTrue(browserSessionIdCookie.isPresent());
        assertThat(browserSessionIdCookie.get().getValue(), not(equalTo(BROWSER_SESSION_ID)));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        AUTHORISATION_REQUEST_RECEIVED,
                        AUTHORISATION_REQUEST_PARSED,
                        AUTHORISATION_INITIATED));
    }

    @Test
    void shouldRedirectToLoginUriWhenCookieHasUnknownSessionId() {
        setupForAuthJourney();
        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                new HttpCookie[] {
                                    buildSessionCookie("123", DUMMY_CLIENT_SESSION_ID),
                                    new HttpCookie("bsid", BROWSER_SESSION_ID)
                                }),
                        constructQueryStringParameters(CLIENT_ID, null, "openid", null),
                        Optional.of("GET"));

        assertThat(response, hasStatus(302));
        String redirectUri = getLocationResponseHeader(response);
        assertThat(
                redirectUri,
                startsWith(TEST_CONFIGURATION_SERVICE.getAuthFrontendBaseURL().toString()));
        var sessionCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs");
        assertOnSessionCookie(sessionCookie);
        assertTrue(
                getHttpCookieFromMultiValueResponseHeaders(
                                response.getMultiValueHeaders(), "di-persistent-session-id")
                        .isPresent());

        Optional<HttpCookie> browserSessionIdCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "bsid");
        assertTrue(browserSessionIdCookie.isPresent());
        assertThat(browserSessionIdCookie.get().getValue(), not(equalTo(BROWSER_SESSION_ID)));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        AUTHORISATION_REQUEST_RECEIVED,
                        AUTHORISATION_REQUEST_PARSED,
                        AUTHORISATION_INITIATED));
    }

    @Test
    void shouldRedirectToLoginUriWhenUserHasPreviousSessionButNoBsidCookie() throws Exception {
        setupForAuthJourney();
        String previousSessionId = givenAnExistingSession(LOW_LEVEL);
        redis.addBrowserSesssionIdToSession(previousSessionId, BROWSER_SESSION_ID);
        registerUser();

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                new HttpCookie[] {
                                    buildSessionCookie(previousSessionId, DUMMY_CLIENT_SESSION_ID),
                                    new HttpCookie("bsid", "some-other-browser-session-id")
                                }),
                        constructQueryStringParameters(CLIENT_ID, null, "openid", "P2.Cl.Cm"),
                        Optional.of("GET"));

        assertThat(response, hasStatus(302));

        String redirectUri = getLocationResponseHeader(response);
        assertThat(
                redirectUri,
                startsWith(TEST_CONFIGURATION_SERVICE.getAuthFrontendBaseURL().toString()));

        System.out.println(response.getMultiValueHeaders());

        assertTrue(
                getHttpCookieFromMultiValueResponseHeaders(
                                response.getMultiValueHeaders(), "di-persistent-session-id")
                        .isPresent());

        var sessionCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs");
        assertOnSessionCookie(sessionCookie, previousSessionId);

        Optional<HttpCookie> browserSessionIdCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "bsid");
        assertTrue(browserSessionIdCookie.isPresent());
        assertThat(browserSessionIdCookie.get().getValue(), not(equalTo(BROWSER_SESSION_ID)));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        AUTHORISATION_REQUEST_RECEIVED,
                        AUTHORISATION_REQUEST_PARSED,
                        AUTHORISATION_INITIATED));
    }

    @Test
    void shouldRedirectToLoginUriWhenUserHasPreviousSession() throws Exception {
        setupForAuthJourney();
        String previousSessionId = givenAnExistingSession(MEDIUM_LEVEL);
        redis.addEmailToSession(previousSessionId, TEST_EMAIL_ADDRESS);
        redis.addBrowserSesssionIdToSession(previousSessionId, BROWSER_SESSION_ID);
        registerUser();
        withExistingOrchSessionAndBsid(previousSessionId);

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                new HttpCookie[] {
                                    buildSessionCookie(previousSessionId, DUMMY_CLIENT_SESSION_ID),
                                    new HttpCookie("bsid", BROWSER_SESSION_ID)
                                }),
                        constructQueryStringParameters(CLIENT_ID, null, "openid", null),
                        Optional.of("GET"));

        assertThat(response, hasStatus(302));
        String redirectUri = getLocationResponseHeader(response);
        assertThat(
                redirectUri,
                startsWith(TEST_CONFIGURATION_SERVICE.getAuthFrontendBaseURL().toString()));
        var sessionCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs");
        assertOnSessionCookie(sessionCookie, previousSessionId);
        assertTrue(
                getHttpCookieFromMultiValueResponseHeaders(
                                response.getMultiValueHeaders(), "di-persistent-session-id")
                        .isPresent());
        Optional<HttpCookie> browserSessionIdCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "bsid");
        assertTrue(browserSessionIdCookie.isPresent());
        assertThat(browserSessionIdCookie.get().getValue(), equalTo(BROWSER_SESSION_ID));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        AUTHORISATION_REQUEST_RECEIVED,
                        AUTHORISATION_REQUEST_PARSED,
                        AUTHORISATION_INITIATED));
    }

    @Test
    void shouldRedirectToLoginUriWhenUserHasPreviousSessionButRequiresIdentity() throws Exception {
        setupForAuthJourney();
        String previousSessionId = givenAnExistingSession(MEDIUM_LEVEL);
        redis.addEmailToSession(previousSessionId, TEST_EMAIL_ADDRESS);
        redis.addBrowserSesssionIdToSession(previousSessionId, BROWSER_SESSION_ID);
        registerUser();
        withExistingOrchSessionAndBsid(previousSessionId);

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                new HttpCookie[] {
                                    buildSessionCookie(previousSessionId, DUMMY_CLIENT_SESSION_ID),
                                    new HttpCookie("bsid", BROWSER_SESSION_ID)
                                }),
                        constructQueryStringParameters(CLIENT_ID, null, "openid", "P2.Cl.Cm"),
                        Optional.of("GET"));

        assertThat(response, hasStatus(302));

        var sessionCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs");
        assertOnSessionCookie(sessionCookie, previousSessionId);
        assertTrue(
                getHttpCookieFromMultiValueResponseHeaders(
                                response.getMultiValueHeaders(), "di-persistent-session-id")
                        .isPresent());

        Optional<HttpCookie> browserSessionIdCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "bsid");
        assertTrue(browserSessionIdCookie.isPresent());
        assertThat(browserSessionIdCookie.get().getValue(), equalTo(BROWSER_SESSION_ID));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        AUTHORISATION_REQUEST_RECEIVED,
                        AUTHORISATION_REQUEST_PARSED,
                        AUTHORISATION_INITIATED));
    }

    @Test
    void shouldReturnInvalidVtrListErrorToRPWhenVtrListContainsBothIdentityAndNonIdentityVectors()
            throws Exception {
        setupForAuthJourney();
        String sessionId = givenAnExistingSession(MEDIUM_LEVEL);
        redis.addEmailToSession(sessionId, TEST_EMAIL_ADDRESS);
        redis.addBrowserSesssionIdToSession(sessionId, BROWSER_SESSION_ID);
        registerUser();

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                new HttpCookie[] {
                                    buildSessionCookie(sessionId, DUMMY_CLIENT_SESSION_ID),
                                    new HttpCookie("bsid", BROWSER_SESSION_ID)
                                }),
                        constructQueryStringParameters(
                                CLIENT_ID, null, "openid", "[P2.Cl.Cm,Cl.Cm]"),
                        Optional.of("GET"));

        assertThat(response, hasStatus(302));
        var redirectUri = getLocationResponseHeader(response);
        assertThat(redirectUri, startsWith(RP_REDIRECT_URI.toString()));
        assertThat(URI.create(redirectUri).getQuery(), containsString("error=invalid_request"));
        assertThat(
                URI.create(redirectUri).getQuery(),
                containsString("error_description=Request+vtr+not+valid"));
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
        assertThat(
                redirectUri,
                startsWith(TEST_CONFIGURATION_SERVICE.getAuthFrontendBaseURL().toString()));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        AUTHORISATION_REQUEST_RECEIVED,
                        AUTHORISATION_REQUEST_PARSED,
                        AUTHORISATION_INITIATED));
    }

    @Test
    void shouldNotPromptForLoginWhenPromptNoneAndUserAuthenticated() throws Exception {
        setupForAuthJourney();
        String previousSessionId = givenAnExistingSession(MEDIUM_LEVEL);
        redis.addEmailToSession(previousSessionId, TEST_EMAIL_ADDRESS);
        redis.addBrowserSesssionIdToSession(previousSessionId, BROWSER_SESSION_ID);
        registerUser();
        withExistingOrchSessionAndBsid(previousSessionId);

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                new HttpCookie[] {
                                    buildSessionCookie(previousSessionId, DUMMY_CLIENT_SESSION_ID),
                                    new HttpCookie("bsid", BROWSER_SESSION_ID)
                                }),
                        constructQueryStringParameters(
                                CLIENT_ID, NONE.toString(), OPENID.getValue(), null),
                        Optional.of("GET"));

        assertThat(response, hasStatus(302));
        var sessionCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs");
        assertOnSessionCookie(sessionCookie, previousSessionId);
        assertTrue(
                getHttpCookieFromMultiValueResponseHeaders(
                                response.getMultiValueHeaders(), "di-persistent-session-id")
                        .isPresent());

        Optional<HttpCookie> browserSessionIdCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "bsid");
        assertTrue(browserSessionIdCookie.isPresent());
        assertThat(browserSessionIdCookie.get().getValue(), startsWith(BROWSER_SESSION_ID));

        assertThat(
                getLocationResponseHeader(response),
                startsWith(TEST_CONFIGURATION_SERVICE.getAuthFrontendBaseURL().toString()));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        AUTHORISATION_REQUEST_RECEIVED,
                        AUTHORISATION_REQUEST_PARSED,
                        AUTHORISATION_INITIATED));
    }

    @Test
    void shouldPromptForLoginWhenPromptLoginAndUserAuthenticated() throws Exception {
        setupForAuthJourney();
        String previousSessionId = givenAnExistingSession(MEDIUM_LEVEL);
        redis.addEmailToSession(previousSessionId, TEST_EMAIL_ADDRESS);
        redis.addBrowserSesssionIdToSession(previousSessionId, BROWSER_SESSION_ID);
        registerUser();
        withExistingOrchSessionAndBsid(previousSessionId);

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                new HttpCookie[] {
                                    buildSessionCookie(previousSessionId, DUMMY_CLIENT_SESSION_ID),
                                    new HttpCookie("bsid", BROWSER_SESSION_ID)
                                }),
                        constructQueryStringParameters(
                                CLIENT_ID, LOGIN.toString(), OPENID.getValue(), null),
                        Optional.of("GET"));

        assertThat(response, hasStatus(302));
        var sessionCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs");
        assertOnSessionCookie(sessionCookie, previousSessionId);
        assertTrue(
                getHttpCookieFromMultiValueResponseHeaders(
                                response.getMultiValueHeaders(), "di-persistent-session-id")
                        .isPresent());

        Optional<HttpCookie> browserSessionIdCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "bsid");
        assertTrue(browserSessionIdCookie.isPresent());
        assertThat(browserSessionIdCookie.get().getValue(), startsWith(BROWSER_SESSION_ID));

        String redirectUri = getLocationResponseHeader(response);
        assertThat(
                redirectUri,
                startsWith(TEST_CONFIGURATION_SERVICE.getAuthFrontendBaseURL().toString()));
        assertThat(URI.create(redirectUri).getQuery(), containsString("prompt=login"));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        AUTHORISATION_REQUEST_RECEIVED,
                        AUTHORISATION_REQUEST_PARSED,
                        AUTHORISATION_INITIATED));
    }

    @Test
    void shouldRequireUpliftWhenHighCredentialLevelOfTrustRequested() throws Exception {
        setupForAuthJourney();
        String previousSessionId = givenAnExistingSession(LOW_LEVEL);
        redis.addEmailToSession(previousSessionId, TEST_EMAIL_ADDRESS);
        redis.addBrowserSesssionIdToSession(previousSessionId, BROWSER_SESSION_ID);
        registerUser();
        withExistingOrchSessionAndBsid(previousSessionId);

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                new HttpCookie[] {
                                    buildSessionCookie(previousSessionId, DUMMY_CLIENT_SESSION_ID),
                                    new HttpCookie("bsid", BROWSER_SESSION_ID)
                                }),
                        constructQueryStringParameters(
                                CLIENT_ID, null, OPENID.getValue(), MEDIUM_LEVEL.getValue()),
                        Optional.of("GET"));

        assertThat(response, hasStatus(302));

        var sessionCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs");
        assertOnSessionCookie(sessionCookie, previousSessionId);
        assertTrue(
                getHttpCookieFromMultiValueResponseHeaders(
                                response.getMultiValueHeaders(), "di-persistent-session-id")
                        .isPresent());

        Optional<HttpCookie> browserSessionIdCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "bsid");
        assertTrue(browserSessionIdCookie.isPresent());
        assertThat(browserSessionIdCookie.get().getValue(), startsWith(BROWSER_SESSION_ID));

        String redirectUri = getLocationResponseHeader(response);
        assertThat(
                redirectUri,
                startsWith(TEST_CONFIGURATION_SERVICE.getAuthFrontendBaseURL().toString()));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        AUTHORISATION_REQUEST_RECEIVED,
                        AUTHORISATION_REQUEST_PARSED,
                        AUTHORISATION_INITIATED));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "en", "cy", "en cy", "es fr ja", "cy-AR"})
    void shouldCallAuthorizeAsDocAppClient(String uiLocales) throws JOSEException, ParseException {
        setupForDocAppJourney();
        registerClient(
                CLIENT_ID,
                "test-client",
                List.of(OPENID.getValue(), CustomScopeValue.DOC_CHECKING_APP.getValue()),
                ClientType.APP,
                false,
                false);
        handler = new AuthorisationHandler(configuration, redisConnectionService);
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
        assertThat(getLocationResponseHeader(response), startsWith(AUTHORIZE_URI.toString()));
        var sessionCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs");
        assertOnSessionCookie(sessionCookie);
        var languageCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "lng");
        if (uiLocales.contains("en")) {
            assertTrue(languageCookie.isPresent());
            assertThat(languageCookie.get().getValue(), equalTo("en"));
        } else if (uiLocales.contains("cy")) {
            assertTrue(languageCookie.isPresent());
            assertThat(languageCookie.get().getValue(), equalTo("cy"));
        } else {
            assertThat(languageCookie.isPresent(), equalTo(false));
        }
        var clientSessionID = sessionCookie.get().getValue().split("\\.")[1];
        var clientSession = redis.getClientSession(clientSessionID);
        var authRequest = AuthenticationRequest.parse(clientSession.getAuthRequestParams());
        assertTrue(authRequest.getScope().contains(CustomScopeValue.DOC_CHECKING_APP));
        assertThat(
                authRequest.getCustomParameter("vtr"),
                equalTo(List.of("[\"P2.Cl.Cm\",\"PCL200.Cl.Cm\"]")));
        assertThat(
                clientSession.getVtrList(),
                equalTo(
                        List.of(
                                VectorOfTrust.of(MEDIUM_LEVEL, LevelOfConfidence.MEDIUM_LEVEL),
                                VectorOfTrust.of(MEDIUM_LEVEL, LevelOfConfidence.HMRC200))));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        AUTHORISATION_REQUEST_RECEIVED,
                        AUTHORISATION_REQUEST_PARSED,
                        DOC_APP_AUTHORISATION_REQUESTED));
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
                List.of(
                        AUTHORISATION_REQUEST_RECEIVED,
                        AUTHORISATION_REQUEST_PARSED,
                        DOC_APP_AUTHORISATION_REQUESTED));
    }

    @Test
    void shouldRedirectToLoginWithValidRequestObjectNonDocApp()
            throws JOSEException, ParseException {
        setupForAuthJourney();
        SignedJWT signedJWT = createSignedJWT("", CLAIMS, List.of("openid"));

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

        assertThat(response, hasStatus(302));
        assertThat(
                getLocationResponseHeader(response),
                startsWith(TEST_CONFIGURATION_SERVICE.getAuthFrontendBaseURL().toString()));

        var sessionCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs");
        var clientSessionID = sessionCookie.get().getValue().split("\\.")[1];
        var clientSession = redis.getClientSession(clientSessionID);
        var authRequest = AuthenticationRequest.parse(clientSession.getAuthRequestParams());

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        AUTHORISATION_REQUEST_RECEIVED,
                        AUTHORISATION_REQUEST_PARSED,
                        AUTHORISATION_INITIATED));
        JsonElement actualClaims =
                JsonParser.parseString(String.valueOf(authRequest.getOIDCClaims()));
        JsonElement expectedClaims = JsonParser.parseString(CLAIMS);
        assertThat(actualClaims, equalTo(expectedClaims));

        assertThat(
                authRequest
                        .getOIDCClaims()
                        .getUserInfoClaimsRequest()
                        .get(CORE_IDENTITY_JWT.getValue())
                        .getClaimRequirement(),
                equalTo(ClaimRequirement.ESSENTIAL));

        assertThat(
                authRequest
                        .getOIDCClaims()
                        .getUserInfoClaimsRequest()
                        .get(ADDRESS.getValue())
                        .getClaimRequirement(),
                equalTo(ClaimRequirement.ESSENTIAL));
    }

    @Test
    void
            shouldRedirectToRedirectUriGivenAnInvalidRequestWhenJARIsRequiredButRequestObjectIsMissingAndRedirectUriIsInClientRegistry() {
        registerClient(
                CLIENT_ID, "test-client", singletonList("openid"), ClientType.WEB, true, false);
        handler = new AuthorisationHandler(configuration);
        txmaAuditQueue.clear();

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(Optional.empty()),
                        constructQueryStringParameters(CLIENT_ID, null, "openid", "Cl.Cm"),
                        Optional.of("GET"));

        var locationHeaderUri = URI.create(response.getHeaders().get("Location"));
        var expectedQueryStringRegex =
                "error=access_denied&error_description=JAR[+]required[+]for[+]client[+]but[+]request[+]does[+]not[+]contain[+]Request[+]Object.*";
        assertThat(response, hasStatus(302));
        assertThat(locationHeaderUri.toString(), containsString(RP_REDIRECT_URI.toString()));
        assertThat(locationHeaderUri.getQuery(), matchesPattern(expectedQueryStringRegex));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_REQUEST_ERROR));
    }

    @Test
    void
            shouldReturnBadRequestGivenAnInvalidRequestWhenJARIsRequiredButRequestObjectIsMissingAndRedirectUriIsNotInClientRegistry() {
        registerClient(
                CLIENT_ID, "test-client", singletonList("openid"), ClientType.WEB, true, false);
        handler = new AuthorisationHandler(configuration);
        txmaAuditQueue.clear();

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(Optional.empty()),
                        constructQueryStringParameters(
                                CLIENT_ID,
                                null,
                                "openid",
                                "Cl.Cm",
                                URI.create("invalid-redirect-uri")),
                        Optional.of("GET"));

        assertThat(response, hasStatus(400));
        assertThat(response.getBody(), equalTo(OAuth2Error.INVALID_REQUEST.getDescription()));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(AUTHORISATION_REQUEST_RECEIVED, AUTHORISATION_REQUEST_ERROR));
    }

    @Test
    void shouldUpdateOrchSessionWhenMaxAgeHasExpired() throws Exception {
        registerClient(
                CLIENT_ID, "test-client", singletonList("openid"), ClientType.WEB, false, true);
        var previousSessionId = givenAnExistingSession(MEDIUM_LEVEL);
        orchSessionExtension.addSession(
                new OrchSessionItem(previousSessionId)
                        .withAuthenticated(true)
                        .withAuthTime(NowHelper.now().toInstant().getEpochSecond() - 10));
        handler = new AuthorisationHandler(configuration, redisConnectionService);
        txmaAuditQueue.clear();

        var previousSession = orchSessionExtension.getSession(previousSessionId);
        assertTrue(previousSession.isPresent());
        assertTrue(previousSession.get().getAuthenticated());
        assertNull(previousSession.get().getPreviousSessionId());

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                new HttpCookie[] {
                                    buildSessionCookie(previousSessionId, DUMMY_CLIENT_SESSION_ID),
                                    new HttpCookie("bsid", BROWSER_SESSION_ID)
                                }),
                        constructQueryStringParameters(CLIENT_ID, null, "openid", "P2.Cl.Cm", 0L),
                        Optional.of("GET"));
        var sessionCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs");
        var newSessionId = sessionCookie.get().getValue().split("\\.")[0];

        var newSession = orchSessionExtension.getSession(newSessionId);
        assertTrue(newSession.isPresent());
        assertFalse(newSession.get().getAuthenticated());
        assertEquals(newSession.get().getSessionId(), newSessionId);
    }

    @Test
    void shouldUpdateSharedSessionWhenMaxAgeExpired() throws Exception {
        registerClient(
                CLIENT_ID, "test-client", singletonList("openid"), ClientType.WEB, false, true);
        var previousClientSessionId = "a-previous-client-session";
        var previousSessionId = givenAnExistingSessionWithClientSession(previousClientSessionId);
        orchSessionExtension.addSession(
                new OrchSessionItem(previousSessionId)
                        .withAuthenticated(true)
                        .withAuthTime(NowHelper.now().toInstant().getEpochSecond() - 10));
        handler = new AuthorisationHandler(configuration, redisConnectionService);
        txmaAuditQueue.clear();

        var previousSession = orchSessionExtension.getSession(previousSessionId);
        assertTrue(previousSession.isPresent());
        assertTrue(previousSession.get().getAuthenticated());
        assertNull(previousSession.get().getPreviousSessionId());

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                new HttpCookie[] {
                                    buildSessionCookie(previousSessionId, DUMMY_CLIENT_SESSION_ID),
                                    new HttpCookie("bsid", BROWSER_SESSION_ID)
                                }),
                        constructQueryStringParameters(CLIENT_ID, null, "openid", "P2.Cl.Cm", 0L),
                        Optional.of("GET"));
        var sessionCookie =
                getHttpCookieFromMultiValueResponseHeaders(response.getMultiValueHeaders(), "gs");
        var newSessionId = sessionCookie.get().getValue().split("\\.")[0];

        var newSession = redis.getSession(newSessionId);
        assertNotNull(newSession);
        assertEquals(1, newSession.getClientSessions().size());
        assertFalse(newSession.getClientSessions().contains(previousClientSessionId));
    }

    @Test
    void shouldReturnInvalidRequestForNegativeMaxAge() throws Exception {
        registerClient(
                CLIENT_ID, "test-client", singletonList("openid"), ClientType.WEB, false, true);
        var previousClientSessionId = "a-previous-client-session";
        var previousSessionId = givenAnExistingSessionWithClientSession(previousClientSessionId);
        orchSessionExtension.addSession(
                new OrchSessionItem(previousSessionId)
                        .withAuthenticated(true)
                        .withAuthTime(NowHelper.now().toInstant().getEpochSecond() - 10));
        handler = new AuthorisationHandler(configuration, redisConnectionService);
        txmaAuditQueue.clear();

        var previousSession = orchSessionExtension.getSession(previousSessionId);
        assertTrue(previousSession.isPresent());
        assertTrue(previousSession.get().getAuthenticated());
        assertNull(previousSession.get().getPreviousSessionId());

        var response =
                makeRequest(
                        Optional.empty(),
                        constructHeaders(
                                new HttpCookie[] {
                                    buildSessionCookie(previousSessionId, DUMMY_CLIENT_SESSION_ID),
                                    new HttpCookie("bsid", BROWSER_SESSION_ID)
                                }),
                        constructQueryStringParameters(
                                CLIENT_ID, null, "openid", "P2.Cl.Cm", -100L),
                        Optional.of("GET"));

        var locationHeaderUri = URI.create(response.getHeaders().get("Location"));
        assertThat(response, hasStatus(302));
        assertThat(locationHeaderUri.toString(), containsString(RP_REDIRECT_URI.toString()));
        assertThat(
                locationHeaderUri.getQuery(),
                containsString(
                        "error=invalid_request&error_description=Max+age+is+negative+in+query+params"));
    }

    @Test
    void shouldReturnInvalidRequestForNegativeMaxAgeInRequestObject() throws JOSEException {
        setupForAuthJourney();
        SignedJWT signedJWT = createSignedJWT("", CLAIMS, List.of("openid"), -100);

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
        assertThat(response, hasStatus(302));
        assertThat(locationHeaderUri.toString(), containsString(RP_REDIRECT_URI.toString()));
        assertThat(
                locationHeaderUri.getQuery(),
                containsString(
                        "error=invalid_request&error_description=Max+age+is+negative+in+request+object"));
    }

    private Map<String, String> constructQueryStringParameters(
            String clientId, String prompt, String scopes, String vtr) {
        return constructQueryStringParameters(
                clientId, prompt, scopes, vtr, null, RP_REDIRECT_URI, null);
    }

    private Map<String, String> constructQueryStringParameters(
            String clientId, String prompt, String scopes, String vtr, Long maxAge) {
        return constructQueryStringParameters(
                clientId, prompt, scopes, vtr, null, RP_REDIRECT_URI, maxAge);
    }

    private Map<String, String> constructQueryStringParameters(
            String clientId, String prompt, String scopes, String vtr, String uiLocales) {
        return constructQueryStringParameters(
                clientId, prompt, scopes, vtr, uiLocales, RP_REDIRECT_URI, null);
    }

    private Map<String, String> constructQueryStringParameters(
            String clientId, String prompt, String scopes, String vtr, URI redirectUri) {
        return constructQueryStringParameters(
                clientId, prompt, scopes, vtr, null, redirectUri, null);
    }

    private Map<String, String> constructQueryStringParameters(
            String clientId,
            String prompt,
            String scopes,
            String vtr,
            String uiLocales,
            URI redirectUri,
            Long maxAge) {
        final Map<String, String> queryStringParameters =
                new HashMap<>(
                        Map.of(
                                "response_type",
                                "code",
                                "redirect_uri",
                                redirectUri.toString(),
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
        Optional.ofNullable(maxAge)
                .ifPresent(s -> queryStringParameters.put("max_age", s.toString()));

        return queryStringParameters;
    }

    private void setupForAuthJourney() {
        registerClient(
                CLIENT_ID,
                "test-client",
                singletonList("openid"),
                ClientType.WEB,
                false,
                false,
                List.of(CORE_IDENTITY_JWT.getValue(), ValidClaims.ADDRESS.getValue()));
        handler = new AuthorisationHandler(configuration, redisConnectionService);
        txmaAuditQueue.clear();
    }

    private void setupForDocAppJourney() {
        registerClient(
                CLIENT_ID,
                "test-client",
                List.of("openid", "doc-checking-app"),
                ClientType.APP,
                false,
                false);
        handler = new AuthorisationHandler(configuration);
        txmaAuditQueue.clear();

        var jwkKey =
                new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                        .keyUse(KeyUse.ENCRYPTION)
                        .keyID(ENCRYPTION_KEY_ID)
                        .build();
        jwksExtension.init(new JWKSet(jwkKey));
    }

    private String givenAnExistingSessionWithClientSession(String clientSessionId)
            throws Json.JsonException {
        var sessionId = redis.createSession();
        redis.addClientSessionIdToSession(clientSessionId, sessionId);
        return sessionId;
    }

    private String givenAnExistingSession(CredentialTrustLevel credentialTrustLevel)
            throws Json.JsonException {
        String sessionId = redis.createSession();
        redis.setSessionCredentialTrustLevel(sessionId, credentialTrustLevel);
        return sessionId;
    }

    private String getLocationResponseHeader(APIGatewayProxyResponseEvent response) {
        return response.getHeaders().get(ResponseHeaders.LOCATION);
    }

    private void registerUser() {
        userStore.signUp(TEST_EMAIL_ADDRESS, TEST_PASSWORD);
    }

    private void registerClient(
            String clientId,
            String clientName,
            List<String> scopes,
            ClientType clientType,
            boolean jarValidationRequired,
            boolean maxAgeEnabled,
            List<String> claimsSupported) {
        clientStore.registerClient(
                clientId,
                clientName,
                singletonList(RP_REDIRECT_URI.toString()),
                singletonList("joe.bloggs@digital.cabinet-office.gov.uk"),
                scopes,
                Base64.getMimeEncoder().encodeToString(KEY_PAIR.getPublic().getEncoded()),
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public",
                clientType,
                claimsSupported,
                jarValidationRequired,
                List.of(
                        LevelOfConfidence.MEDIUM_LEVEL.getValue(),
                        LevelOfConfidence.HMRC200.getValue()),
                maxAgeEnabled);
    }

    private void registerClient(
            String clientId,
            String clientName,
            List<String> scopes,
            ClientType clientType,
            boolean jarValidationRequired,
            boolean maxAgeEnabled) {
        registerClient(
                clientId,
                clientName,
                scopes,
                clientType,
                jarValidationRequired,
                maxAgeEnabled,
                emptyList());
    }

    private SignedJWT createSignedJWT(String uiLocales) throws JOSEException {
        return createSignedJWT(uiLocales, null, null);
    }

    private SignedJWT createSignedJWT(String uiLocales, String claims, List<String> scopes)
            throws JOSEException {
        return createSignedJWT(uiLocales, claims, scopes, null);
    }

    private SignedJWT createSignedJWT(
            String uiLocales, String claims, List<String> scopes, Integer maxAge)
            throws JOSEException {
        var jwtClaimsSetBuilder =
                new JWTClaimsSet.Builder()
                        .audience("http://localhost/authorize")
                        .claim("redirect_uri", RP_REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim(
                                "scope",
                                Objects.nonNull(scopes)
                                        ? Scope.parse(scopes).toString()
                                        : new Scope(
                                                        OIDCScopeValue.OPENID,
                                                        CustomScopeValue.DOC_CHECKING_APP)
                                                .toString())
                        .claim("nonce", new Nonce().getValue())
                        .claim("client_id", CLIENT_ID)
                        .claim("state", new State().getValue())
                        .claim("vtr", List.of("P2.Cl.Cm", "PCL200.Cl.Cm"))
                        .issuer(CLIENT_ID);

        if (claims != null && !claims.isBlank()) {
            jwtClaimsSetBuilder.claim("claims", claims);
        }
        if (uiLocales != null && !uiLocales.isBlank()) {
            jwtClaimsSetBuilder.claim("ui_locales", uiLocales);
        }

        if (maxAge != null) {
            jwtClaimsSetBuilder.claim("max_age", maxAge);
        }
        var jwsHeader = new JWSHeader(JWSAlgorithm.RS256);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSetBuilder.build());
        var signer = new RSASSASigner(KEY_PAIR.getPrivate());
        signedJWT.sign(signer);
        return signedJWT;
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

    private void withExistingOrchSessionAndBsid(String sessionId) {
        orchSessionExtension.addSession(
                new OrchSessionItem(sessionId)
                        .withBrowserSessionId(BROWSER_SESSION_ID)
                        .withAuthenticated(true));
        assertTrue(orchSessionExtension.getSession(sessionId).isPresent());
    }

    private void assertOnSessionCookie(
            Optional<HttpCookie> sessionCookie, String previousSessionId) {
        assertOnSessionCookie(sessionCookie);
        assertThat(sessionCookie.get().getValue(), not(startsWith(previousSessionId)));
        assertTrue(orchSessionExtension.getSession(previousSessionId).isEmpty());
    }

    private void assertOnSessionCookie(Optional<HttpCookie> sessionCookie) {
        assertTrue(sessionCookie.isPresent());
        var sessionId = sessionCookie.get().getValue().split("\\.")[0];
        assertTrue(orchSessionExtension.getSession(sessionId).isPresent());
    }
}
