package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.ProxyRequestContext;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.RequestIdentity;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCError;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import org.apache.logging.log4j.core.LogEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.MockedStatic;
import uk.gov.di.authentication.app.domain.DocAppAuditableEvent;
import uk.gov.di.authentication.oidc.domain.OidcAuditableEvent;
import uk.gov.di.authentication.oidc.entity.AuthRequestError;
import uk.gov.di.authentication.oidc.exceptions.IncorrectRedirectUriException;
import uk.gov.di.authentication.oidc.exceptions.InvalidAuthenticationRequestException;
import uk.gov.di.authentication.oidc.exceptions.InvalidHttpMethodException;
import uk.gov.di.authentication.oidc.exceptions.MissingClientIDException;
import uk.gov.di.authentication.oidc.exceptions.MissingRedirectUriException;
import uk.gov.di.authentication.oidc.services.AuthorisationService;
import uk.gov.di.authentication.oidc.services.OrchestrationAuthorizationService;
import uk.gov.di.authentication.oidc.validators.QueryParamsAuthorizeValidator;
import uk.gov.di.authentication.oidc.validators.RequestObjectAuthorizeValidator;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.api.AuthFrontend;
import uk.gov.di.orchestration.shared.domain.AuditableEvent;
import uk.gov.di.orchestration.shared.entity.*;
import uk.gov.di.orchestration.shared.exceptions.ClientNotFoundException;
import uk.gov.di.orchestration.shared.exceptions.ClientRedirectUriValidationException;
import uk.gov.di.orchestration.shared.exceptions.ClientSignatureValidationException;
import uk.gov.di.orchestration.shared.exceptions.JwksException;
import uk.gov.di.orchestration.shared.helpers.DocAppSubjectIdHelper;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.ClientService;
import uk.gov.di.orchestration.shared.services.ClientSessionService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DocAppAuthorisationService;
import uk.gov.di.orchestration.shared.services.NoSessionOrchestrationService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.SessionService;
import uk.gov.di.orchestration.shared.services.TokenValidationService;
import uk.gov.di.orchestration.shared.state.UserContext;
import uk.gov.di.orchestration.sharedtest.helper.KeyPairHelper;
import uk.gov.di.orchestration.sharedtest.helper.TokenGeneratorHelper;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.text.ParseException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static com.nimbusds.oauth2.sdk.OAuth2Error.INVALID_REQUEST;
import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.oidc.domain.OidcAuditableEvent.AUTHORISATION_REQUEST_ERROR;
import static uk.gov.di.authentication.oidc.helper.RequestObjectTestHelper.generateSignedJWT;
import static uk.gov.di.orchestration.shared.helpers.PersistentIdHelper.isValidPersistentSessionCookieWithDoubleDashedTimestamp;
import static uk.gov.di.orchestration.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.orchestration.sharedtest.helper.JsonArrayHelper.jsonArrayOf;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.hasContextData;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withMessage;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthorisationHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final DocAppAuthorisationService docAppAuthorisationService =
            mock(DocAppAuthorisationService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ClientSession clientSession = mock(ClientSession.class);
    private final OrchestrationAuthorizationService orchestrationAuthorizationService =
            mock(OrchestrationAuthorizationService.class);
    private final UserContext userContext = mock(UserContext.class);
    private final AuditService auditService = mock(AuditService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final AuthFrontend authFrontend = mock(AuthFrontend.class);
    private final AuthorisationService authorisationService = mock(AuthorisationService.class);
    private final OrchSessionService orchSessionService = mock(OrchSessionService.class);
    protected final Json objectMapper = SerializationService.getInstance();

    private final NoSessionOrchestrationService noSessionOrchestrationService =
            mock(NoSessionOrchestrationService.class);
    private final TokenValidationService tokenValidationService =
            mock(TokenValidationService.class);
    private final RequestObjectAuthorizeValidator requestObjectAuthorizeValidator =
            mock(RequestObjectAuthorizeValidator.class);
    private final QueryParamsAuthorizeValidator queryParamsAuthorizeValidator =
            mock(QueryParamsAuthorizeValidator.class);
    private final ClientService clientService = mock(ClientService.class);
    private final InOrder inOrder = inOrder(auditService);
    private static final String EXPECTED_SESSION_COOKIE_STRING =
            "gs=a-session-id.client-session-id; Max-Age=3600; Domain=auth.ida.digital.cabinet-office.gov.uk; Secure; HttpOnly;";
    private static final String EXPECTED_BASE_PERSISTENT_COOKIE_VALUE = IdGenerator.generate();
    private static final String ARBITRARY_UNIX_TIMESTAMP = "1700558480962";
    private static final String EXPECTED_PERSISTENT_COOKIE_VALUE_WITH_TIMESTAMP =
            EXPECTED_BASE_PERSISTENT_COOKIE_VALUE + "--" + ARBITRARY_UNIX_TIMESTAMP;
    private static final String EXPECTED_LANGUAGE_COOKIE_STRING =
            "lng=en; Max-Age=31536000; Domain=auth.ida.digital.cabinet-office.gov.uk; Secure; HttpOnly;";
    private static final URI FRONT_END_BASE_URI = URI.create("https://example.com");
    private static final URI FRONT_END_ERROR_URI = URI.create("https://example.com/error");
    private static final URI FRONT_END_AUTHORIZE_URI = URI.create("https://example.com/authorize");
    private static final URI FRONT_END_AUTHORIZE_LOGIN_URI =
            URI.create("https://example.com/authorize?prompt=login");
    private static final URI FRONT_END_AUTHORIZE_SIGN_IN_URI =
            URI.create("https://example.com/authorize?result=sign-in");
    private static final String AWS_REQUEST_ID = "aws-request-id";
    private static final ClientID CLIENT_ID = new ClientID("test-id");
    private static final String SESSION_ID = "a-session-id";
    private static final String NEW_SESSION_ID = "a-new-session-id";
    private static final String BROWSER_SESSION_ID_COOKIE_NAME = "bsid";
    private static final String BROWSER_SESSION_ID = "a-browser-session-id";
    private static final String DIFFERENT_BROWSER_SESSION_ID = "a--different-browser-session-id";
    private static final String NEW_BROWSER_SESSION_ID = "a-new-browser-session-id";
    private static final String REDIRECT_URI = "https://localhost:8080";
    private static final String DOC_APP_REDIRECT_URI = "/doc-app-authorisation";
    private static final String SCOPE = "email openid profile";
    private static final String CLAIMS =
            "{\"userinfo\":{\"https://vocab.account.gov.uk/v1/coreIdentityJWT\":{\"essential\":true},\"https://vocab.account.gov.uk/v1/address\":null}}";
    private static final String RESPONSE_TYPE = "code";
    private static final String TEST_ORCHESTRATOR_CLIENT_ID = "test-orch-client-id";
    private static final String RP_CLIENT_NAME = "test-rp-client-name";
    private static final EncryptedJWT TEST_ENCRYPTED_JWT;
    private static final Boolean IS_ONE_LOGIN = false;
    private static final Boolean IS_COOKIE_CONSENT_SHARED = false;
    private static final String RP_SERVICE_TYPE = "MANDATORY";
    private static final KeyPair RSA_KEY_PAIR = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
    private static final ECKey EC_SIGNING_KEY = generateECSigningKey();

    static {
        try {
            TEST_ENCRYPTED_JWT = createEncryptedJWT();
        } catch (JOSEException | ParseException e) {
            throw new RuntimeException(e);
        }
    }

    private Session session;
    private OrchSessionItem orchSession;
    private static final String CLIENT_SESSION_ID = "client-session-id";
    private static final State STATE = new State();
    private static final Nonce NONCE = new Nonce();
    private static final Subject SUBJECT = new Subject();
    private static final String SERIALIZED_SIGNED_ID_TOKEN =
            TokenGeneratorHelper.generateIDToken(
                            CLIENT_ID.getValue(),
                            SUBJECT,
                            "http://localhost-rp",
                            CLIENT_SESSION_ID,
                            EC_SIGNING_KEY)
                    .serialize();
    private static final String ID_TOKEN_AUDIENCE = getIdTokenAudience();
    private static final String TXMA_ENCODED_HEADER_VALUE = "dGVzdAo=";
    private static final TxmaAuditUser BASE_AUDIT_USER =
            TxmaAuditUser.user()
                    .withGovukSigninJourneyId(CLIENT_SESSION_ID)
                    .withIpAddress("123.123.123.123")
                    .withPersistentSessionId(EXPECTED_PERSISTENT_COOKIE_VALUE_WITH_TIMESTAMP);

    private AuthorisationHandler handler;

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(AuthorisationHandler.class);

    @BeforeEach
    public void setUp() {
        when(configService.getEnvironment()).thenReturn("test-env");
        when(configService.getDomainName()).thenReturn("auth.ida.digital.cabinet-office.gov.uk");
        when(configService.getOidcDomainName())
                .thenReturn("oidc.auth.ida.digital.cabinet-office.gov.uk");
        when(configService.getOrchestrationClientId()).thenReturn(TEST_ORCHESTRATOR_CLIENT_ID);
        when(configService.getSessionCookieAttributes()).thenReturn("Secure; HttpOnly;");
        when(configService.getSessionCookieMaxAge()).thenReturn(3600);
        when(configService.getPersistentCookieMaxAge()).thenReturn(34190000);
        when(configService.isIdentityEnabled()).thenReturn(true);
        when(authFrontend.baseURI()).thenReturn(FRONT_END_BASE_URI);
        when(authFrontend.errorURI()).thenReturn(FRONT_END_ERROR_URI);
        when(authFrontend.authorizeURI(Optional.empty(), Optional.empty()))
                .thenReturn(FRONT_END_AUTHORIZE_URI);
        when(authFrontend.authorizeURI(Optional.of(Prompt.Type.LOGIN), Optional.empty()))
                .thenReturn(FRONT_END_AUTHORIZE_LOGIN_URI);
        when(authFrontend.authorizeURI(Optional.of(Prompt.Type.LOGIN), Optional.empty()))
                .thenReturn(FRONT_END_AUTHORIZE_LOGIN_URI);
        when(authFrontend.authorizeURI(Optional.empty(), Optional.of("sign-in")))
                .thenReturn(FRONT_END_AUTHORIZE_SIGN_IN_URI);
        when(queryParamsAuthorizeValidator.validate(any(AuthenticationRequest.class)))
                .thenReturn(Optional.empty());
        when(orchestrationAuthorizationService.getExistingOrCreateNewPersistentSessionId(any()))
                .thenReturn(EXPECTED_PERSISTENT_COOKIE_VALUE_WITH_TIMESTAMP);
        when(orchestrationAuthorizationService.getVtrList(any())).thenCallRealMethod();
        when(userContext.getClient()).thenReturn(Optional.of(generateClientRegistry()));
        when(context.getAwsRequestId()).thenReturn(AWS_REQUEST_ID);
        handler =
                new AuthorisationHandler(
                        configService,
                        sessionService,
                        orchSessionService,
                        clientSessionService,
                        orchestrationAuthorizationService,
                        auditService,
                        queryParamsAuthorizeValidator,
                        requestObjectAuthorizeValidator,
                        clientService,
                        docAppAuthorisationService,
                        cloudwatchMetricsService,
                        noSessionOrchestrationService,
                        tokenValidationService,
                        authFrontend,
                        authorisationService);
        session = new Session(SESSION_ID);
        orchSession = new OrchSessionItem(SESSION_ID);
        when(sessionService.generateSession()).thenReturn(session);
        when(clientSessionService.generateClientSessionId()).thenReturn(CLIENT_SESSION_ID);
        when(clientSessionService.generateClientSession(any(), any(), any(), any()))
                .thenReturn(clientSession);
        when(clientSession.getDocAppSubjectId()).thenReturn(new Subject("test-subject-id"));
        when(clientService.getClient(anyString()))
                .thenReturn(Optional.of(generateClientRegistry()));
    }

    @Nested
    class AuthJourney {

        @Test
        void shouldRedirectToLoginWhenUserHasNoExistingSession() {
            Map<String, String> requestParams = buildRequestParams(null);
            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            APIGatewayProxyResponseEvent response = makeHandlerRequest(event);
            URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

            assertThat(response, hasStatus(302));
            assertThat(uri.getQuery(), not(containsString("cookie_consent")));
            assertEquals(FRONT_END_BASE_URI.getAuthority(), uri.getAuthority());
            assertTrue(
                    response.getMultiValueHeaders()
                            .get(ResponseHeaders.SET_COOKIE)
                            .contains(EXPECTED_SESSION_COOKIE_STRING));
            var diPersistentCookieString =
                    response.getMultiValueHeaders().get(ResponseHeaders.SET_COOKIE).get(1);
            var sessionId =
                    extractSessionId(
                            diPersistentCookieString, EXPECTED_BASE_PERSISTENT_COOKIE_VALUE);
            assertTrue(isValidPersistentSessionCookieWithDoubleDashedTimestamp(sessionId));
            verify(sessionService).storeOrUpdateSession(eq(session));
            verify(orchSessionService).addSession(any());
            verify(clientSessionService).storeClientSession(CLIENT_SESSION_ID, clientSession);

            inOrder.verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER.withSessionId(session.getSessionId()),
                            pair("client-name", RP_CLIENT_NAME),
                            pair("new_authentication_required", false));
        }

        @Test
        void shouldRedirectToLoginWhenUserHasNoExistingSessionWithSignedAndEncryptedJwtInBody() {
            var orchClientId = "orchestration-client-id";
            when(configService.getOrchestrationClientId()).thenReturn(orchClientId);
            when(orchestrationAuthorizationService.getSignedAndEncryptedJWT(any()))
                    .thenReturn(TEST_ENCRYPTED_JWT);

            var requestParams = buildRequestParams(null);
            var event = withRequestEvent(requestParams);
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            var response = makeHandlerRequest(event);

            assertThat(response, hasStatus(302));
            var locationHeader = response.getHeaders().get(ResponseHeaders.LOCATION);
            verify(orchestrationAuthorizationService)
                    .storeState(eq(session.getSessionId()), any(State.class));
            assertThat(locationHeader, containsString(TEST_ENCRYPTED_JWT.serialize()));
            assertThat(
                    splitQuery(locationHeader).get("request"),
                    equalTo(TEST_ENCRYPTED_JWT.serialize()));
            assertThat(splitQuery(locationHeader).get("client_id"), equalTo(orchClientId));
            assertThat(
                    splitQuery(locationHeader).get("response_type"),
                    equalTo(ResponseType.CODE.toString()));
            var captor = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(captor.capture());
            assertEquals(
                    "{\"userinfo\":{\"email_verified\":null,\"email\":null}}",
                    captor.getValue().getClaim("claim"));
        }

        @Test
        void shouldPassTheCorrectClaimsToAuth()
                throws com.nimbusds.oauth2.sdk.ParseException, ParseException {
            var orchClientId = "orchestration-client-id";
            when(configService.getOrchestrationClientId()).thenReturn(orchClientId);
            when(orchestrationAuthorizationService.getSignedAndEncryptedJWT(any()))
                    .thenReturn(TEST_ENCRYPTED_JWT);

            var requestParams =
                    buildRequestParams(
                            Map.of("scope", "openid profile phone", "vtr", "[\"Cl.Cm.P2\"]"));
            var event = withRequestEvent(requestParams);
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            var response = makeHandlerRequest(event);

            assertThat(response, hasStatus(302));
            var locationHeader = response.getHeaders().get(ResponseHeaders.LOCATION);
            verify(orchestrationAuthorizationService)
                    .storeState(eq(session.getSessionId()), any(State.class));
            assertThat(locationHeader, containsString(TEST_ENCRYPTED_JWT.serialize()));
            assertThat(
                    splitQuery(locationHeader).get("request"),
                    equalTo(TEST_ENCRYPTED_JWT.serialize()));
            assertThat(splitQuery(locationHeader).get("client_id"), equalTo(orchClientId));
            assertThat(
                    splitQuery(locationHeader).get("response_type"),
                    equalTo(ResponseType.CODE.toString()));
            var captor = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(captor.capture());
            var expectedClaimSetRequest =
                    ClaimsSetRequest.parse(
                            "{\"userinfo\":{\"salt\":null,\"email_verified\":null,\"local_account_id\":null,\"phone_number_verified\":null,\"phone_number\":null,\"email\":null}}");
            var actualClaimSetRequest =
                    ClaimsSetRequest.parse(captor.getValue().getStringClaim("claim"));
            assertEquals(
                    expectedClaimSetRequest.toJSONObject(), actualClaimSetRequest.toJSONObject());
        }

        @Test
        void shouldPassTheChannelClaimToAuth() {
            var requestParams =
                    buildRequestParams(
                            Map.of("scope", "openid profile phone", "vtr", "[\"Cl.Cm.P2\"]"));
            var event = withRequestEvent(requestParams);
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            makeHandlerRequest(event);

            var captor = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(captor.capture());
            var actualChannelClaim = captor.getValue().getClaim("channel");
            assertEquals(Channel.WEB.getValue(), actualChannelClaim);
        }

        @ParameterizedTest
        @ValueSource(booleans = {true, false})
        void shouldPassAuthenticatedClaimToAuthFromSession(boolean isAuthenticated) {
            withExistingSession(new Session(NEW_SESSION_ID).setAuthenticated(isAuthenticated));

            var requestParams =
                    buildRequestParams(
                            Map.of("scope", "openid profile phone", "vtr", "[\"Cl.Cm.P2\"]"));
            var event = withRequestEvent(requestParams);
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            makeHandlerRequest(event);

            var captor = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(captor.capture());
            var actualChannelClaim = captor.getValue().getClaim("authenticated");
            assertEquals(isAuthenticated, actualChannelClaim);
        }

        @Test
        void authenticatedClaimIsFalseIfNewSession() {
            withNoSession();

            var requestParams =
                    buildRequestParams(
                            Map.of("scope", "openid profile phone", "vtr", "[\"Cl.Cm.P2\"]"));
            var event = withRequestEvent(requestParams);
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            makeHandlerRequest(event);

            var captor = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(captor.capture());
            var actualChannelClaim = captor.getValue().getClaim("authenticated");
            assertEquals(false, actualChannelClaim);
        }

        @Test
        void shouldPassCurrentCredentialStrengthClaimToAuthFromSession() {
            var currentCredentialStrength = CredentialTrustLevel.MEDIUM_LEVEL;
            withExistingSession(
                    new Session(NEW_SESSION_ID)
                            .setCurrentCredentialStrength(currentCredentialStrength));

            var requestParams =
                    buildRequestParams(
                            Map.of("scope", "openid profile phone", "vtr", "[\"Cl.Cm.P2\"]"));
            var event = withRequestEvent(requestParams);
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            makeHandlerRequest(event);

            var captor = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(captor.capture());
            var actualCurrentCredentialStrengthClaim =
                    captor.getValue().getClaim("current_credential_strength");
            assertEquals(currentCredentialStrength, actualCurrentCredentialStrengthClaim);
        }

        @Test
        void shouldPassNullCurrentCredentialStrengthClaimIfNewSession() {
            withNoSession();

            var requestParams =
                    buildRequestParams(
                            Map.of("scope", "openid profile phone", "vtr", "[\"Cl.Cm.P2\"]"));
            var event = withRequestEvent(requestParams);
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            makeHandlerRequest(event);

            var captor = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(captor.capture());
            var actualCurrentCredentialStrengthClaim =
                    captor.getValue().getClaim("current_credential_strength");
            assertEquals(null, actualCurrentCredentialStrengthClaim);
        }

        @ParameterizedTest
        @ValueSource(
                strings = {
                    "",
                    "en",
                    "cy",
                    "en cy",
                    "es fr ja",
                    "es en de",
                    "cy-AR",
                    "en cy cy-AR",
                    "zh-cmn-Hans-CN de-DE fr"
                })
        void shouldRedirectToLoginWhenUserHasNoExistingSessionAndHaveCorrectLangCookie(
                String uiLocales) {

            when(configService.getLanguageCookieMaxAge()).thenReturn(Integer.parseInt("31536000"));

            Map<String, String> requestParams = buildRequestParams(null);
            if (!uiLocales.isBlank()) {
                requestParams.put("ui_locales", uiLocales);
            }
            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            APIGatewayProxyResponseEvent response = makeHandlerRequest(event);
            URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

            assertThat(response, hasStatus(302));
            assertThat(uri.getQuery(), not(containsString("cookie_consent")));
            assertEquals(FRONT_END_BASE_URI.getAuthority(), uri.getAuthority());
            assertTrue(
                    response.getMultiValueHeaders()
                            .get(ResponseHeaders.SET_COOKIE)
                            .contains(EXPECTED_SESSION_COOKIE_STRING));
            var diPersistentCookieString =
                    response.getMultiValueHeaders().get(ResponseHeaders.SET_COOKIE).get(1);
            var sessionId =
                    extractSessionId(
                            diPersistentCookieString, EXPECTED_BASE_PERSISTENT_COOKIE_VALUE);
            assertTrue(isValidPersistentSessionCookieWithDoubleDashedTimestamp(sessionId));
            if (uiLocales.contains("en")) {
                assertTrue(
                        response.getMultiValueHeaders()
                                .get(ResponseHeaders.SET_COOKIE)
                                .contains(EXPECTED_LANGUAGE_COOKIE_STRING));
            } else {
                assertFalse(
                        response.getMultiValueHeaders()
                                .get(ResponseHeaders.SET_COOKIE)
                                .contains("lng="));
            }

            verify(sessionService).storeOrUpdateSession(session);
            verify(clientSessionService).storeClientSession(CLIENT_SESSION_ID, clientSession);

            inOrder.verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER.withSessionId(session.getSessionId()),
                            pair("client-name", RP_CLIENT_NAME),
                            pair("new_authentication_required", false));
        }

        @Test
        void shouldRedirectToLoginWithPromptParamWhenSetToLoginAndExistingSessionIsPresent() {
            withExistingSession(session);
            when(userContext.getClientSession()).thenReturn(clientSession);
            when(userContext.getSession()).thenReturn(session);
            when(clientSession.getAuthRequestParams())
                    .thenReturn(generateAuthRequest(Optional.empty()).toParameters());

            Map<String, String> requestParams = buildRequestParams(Map.of("prompt", "login"));
            APIGatewayProxyResponseEvent response =
                    makeHandlerRequest(withRequestEvent(requestParams));
            URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

            assertThat(response, hasStatus(302));
            assertEquals(FRONT_END_BASE_URI.getAuthority(), uri.getAuthority());
            assertThat(uri.getQuery(), containsString("prompt=login"));

            assertTrue(
                    response.getMultiValueHeaders()
                            .get(ResponseHeaders.SET_COOKIE)
                            .contains(EXPECTED_SESSION_COOKIE_STRING));
            var diPersistentCookieString =
                    response.getMultiValueHeaders().get(ResponseHeaders.SET_COOKIE).get(1);
            var sessionId =
                    extractSessionId(
                            diPersistentCookieString, EXPECTED_BASE_PERSISTENT_COOKIE_VALUE);
            assertTrue(isValidPersistentSessionCookieWithDoubleDashedTimestamp(sessionId));

            verify(sessionService).storeOrUpdateSession(eq(session));
            verify(orchSessionService)
                    .addOrUpdateSessionId(
                            Optional.of(orchSession.getSessionId()), session.getSessionId());
            verify(orchSessionService).updateSession(orchSession);
            verify(clientSessionService).storeClientSession(CLIENT_SESSION_ID, clientSession);

            inOrder.verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER.withSessionId(session.getSessionId()),
                            pair("client-name", RP_CLIENT_NAME),
                            pair("new_authentication_required", false));
        }

        @ParameterizedTest
        @ValueSource(booleans = {true, false})
        void shouldRetainGoogleAnalyticsParamThroughRedirectToLoginWhenClientIsFaceToFaceRp(
                boolean isAuthOrchSplitEnabled) {
            withExistingSession(session);
            when(userContext.getClientSession()).thenReturn(clientSession);
            when(userContext.getSession()).thenReturn(session);
            when(clientSession.getAuthRequestParams())
                    .thenReturn(generateAuthRequest(Optional.empty()).toParameters());

            Map<String, String> requestParams =
                    buildRequestParams(
                            Map.of(
                                    "an-irrelevant-key",
                                    "an-irrelevant-value",
                                    "result",
                                    "sign-in"));
            APIGatewayProxyResponseEvent response =
                    makeHandlerRequest(withRequestEvent(requestParams));
            URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

            assertThat(response, hasStatus(302));
            assertEquals(FRONT_END_BASE_URI.getAuthority(), uri.getAuthority());
            assertThat(uri.getQuery(), containsString("result=sign-in"));
            assertThat(
                    uri.getQuery(), not(containsString("an-irrelevant-key=an-irrelevant-value")));
        }

        @Test
        void shouldRedirectToLoginWhenUserNeedsToBeUplifted() {
            session.setCurrentCredentialStrength(CredentialTrustLevel.LOW_LEVEL);
            withExistingSession(session);
            when(userContext.getClientSession()).thenReturn(clientSession);
            when(userContext.getSession()).thenReturn(session);
            when(clientSession.getAuthRequestParams())
                    .thenReturn(
                            generateAuthRequest(Optional.of(jsonArrayOf("Cl.Cm"))).toParameters());

            APIGatewayProxyResponseEvent response =
                    makeHandlerRequest(
                            withRequestEvent(buildRequestParams(Map.of("vtr", "[\"Cl\"]"))));
            URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

            assertThat(response, hasStatus(302));
            assertEquals(FRONT_END_BASE_URI.getAuthority(), uri.getAuthority());

            assertTrue(
                    response.getMultiValueHeaders()
                            .get(ResponseHeaders.SET_COOKIE)
                            .contains(EXPECTED_SESSION_COOKIE_STRING));

            var diPersistentCookieString =
                    response.getMultiValueHeaders().get(ResponseHeaders.SET_COOKIE).get(1);
            var sessionId =
                    extractSessionId(
                            diPersistentCookieString, EXPECTED_BASE_PERSISTENT_COOKIE_VALUE);
            assertTrue(isValidPersistentSessionCookieWithDoubleDashedTimestamp(sessionId));

            verify(sessionService).storeOrUpdateSession(eq(session));
            verify(orchSessionService)
                    .addOrUpdateSessionId(
                            Optional.of(orchSession.getSessionId()), session.getSessionId());
            verify(orchSessionService).updateSession(orchSession);
            verify(clientSessionService).storeClientSession(CLIENT_SESSION_ID, clientSession);

            inOrder.verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER.withSessionId(session.getSessionId()),
                            pair("client-name", RP_CLIENT_NAME),
                            pair("new_authentication_required", false));
        }

        @Test
        void shouldRedirectToLoginWhenIdentityIsPresentInVtr() {
            withExistingSession(session);
            when(userContext.getClientSession()).thenReturn(clientSession);
            when(userContext.getSession()).thenReturn(session);
            when(clientSession.getAuthRequestParams())
                    .thenReturn(
                            generateAuthRequest(Optional.of(jsonArrayOf("P2.Cl.Cm")))
                                    .toParameters());

            APIGatewayProxyResponseEvent response =
                    makeHandlerRequest(
                            withRequestEvent(buildRequestParams(Map.of("vtr", "[\"P2.Cl.Cm\"]"))));
            URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

            assertThat(response, hasStatus(302));
            assertEquals(FRONT_END_BASE_URI.getAuthority(), uri.getAuthority());

            assertTrue(
                    response.getMultiValueHeaders()
                            .get(ResponseHeaders.SET_COOKIE)
                            .contains(EXPECTED_SESSION_COOKIE_STRING));

            var diPersistentCookieString =
                    response.getMultiValueHeaders().get(ResponseHeaders.SET_COOKIE).get(1);
            var sessionId =
                    extractSessionId(
                            diPersistentCookieString, EXPECTED_BASE_PERSISTENT_COOKIE_VALUE);
            assertTrue(isValidPersistentSessionCookieWithDoubleDashedTimestamp(sessionId));

            verify(sessionService).storeOrUpdateSession(eq(session));
            verify(orchSessionService)
                    .addOrUpdateSessionId(
                            Optional.of(orchSession.getSessionId()), session.getSessionId());
            verify(orchSessionService).updateSession(orchSession);
            verify(clientSessionService).storeClientSession(CLIENT_SESSION_ID, clientSession);

            inOrder.verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER.withSessionId(session.getSessionId()),
                            pair("client-name", RP_CLIENT_NAME),
                            pair("new_authentication_required", false));
        }

        @Test
        void shouldReturnBadRequestWhenClientIsNotPresent() throws JOSEException {
            when(clientService.getClient(CLIENT_ID.getValue())).thenReturn(Optional.empty());

            var response = makeDocAppHandlerRequest();

            assertThat(response.getStatusCode(), equalTo(400));
            assertThat(response.getBody(), equalTo(INVALID_REQUEST.getDescription()));

            verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_REQUEST_ERROR,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER,
                            pair(
                                    "description",
                                    format(
                                            "No Client found for ClientID: %s",
                                            CLIENT_ID.getValue())));

            assertThat(
                    logging.events(),
                    hasItem(
                            withMessage(
                                    format(
                                            "Bad request: No Client found for ClientID: %s",
                                            CLIENT_ID.getValue()))));
            verifyNoInteractions(configService);
            verifyNoInteractions(requestObjectAuthorizeValidator);
        }

        @Test
        void shouldCallClassifyParseExceptionWhenAuthorisationRequestCannotBeParsed()
                throws InvalidAuthenticationRequestException,
                        ClientNotFoundException,
                        MissingClientIDException,
                        IncorrectRedirectUriException,
                        MissingRedirectUriException {
            doThrow(
                            new InvalidAuthenticationRequestException(
                                    new com.nimbusds.oauth2.sdk.ParseException(
                                                    "Missing response_type parameter")
                                            .getErrorObject()))
                    .when(authorisationService)
                    .classifyParseException(any());

            APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
            event.setHttpMethod("GET");
            event.setQueryStringParameters(
                    Map.of(
                            "client_id",
                            CLIENT_ID.getValue(),
                            "redirect_uri",
                            REDIRECT_URI,
                            "scope",
                            SCOPE,
                            "invalid_parameter",
                            "nonsense",
                            "state",
                            STATE.getValue()));
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));

            makeHandlerRequest(event);

            ArgumentCaptor<com.nimbusds.oauth2.sdk.ParseException> parseExceptionArgument =
                    ArgumentCaptor.forClass(com.nimbusds.oauth2.sdk.ParseException.class);

            verify(authorisationService).classifyParseException(parseExceptionArgument.capture());
            assertEquals(
                    "Missing response_type parameter",
                    parseExceptionArgument.getValue().getMessage());
        }

        @Test
        void shouldReturn400WhenAuthorisationRequestContainsInvalidScope() {
            when(queryParamsAuthorizeValidator.validate(any(AuthenticationRequest.class)))
                    .thenReturn(
                            Optional.of(
                                    new AuthRequestError(
                                            OAuth2Error.INVALID_SCOPE,
                                            URI.create("http://localhost:8080"),
                                            new State("test-state"))));

            APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
            event.setHttpMethod("GET");
            event.setQueryStringParameters(
                    Map.of(
                            "client_id", "test-id",
                            "redirect_uri", "http://localhost:8080",
                            "scope", "email,openid,profile,non-existent-scope",
                            "response_type", "code",
                            "state", "test-state"));
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            APIGatewayProxyResponseEvent response = makeHandlerRequest(event);

            assertThat(response, hasStatus(302));
            assertEquals(
                    "http://localhost:8080?error=invalid_scope&error_description=Invalid%2C+unknown+or+malformed+scope&state=test-state",
                    response.getHeaders().get(ResponseHeaders.LOCATION));

            verify(auditService)
                    .submitAuditEvent(
                            AUTHORISATION_REQUEST_ERROR,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER,
                            pair("description", OAuth2Error.INVALID_SCOPE.getDescription()));
        }

        @Test
        void shouldReturn400WhenAuthorisationRequestContainsInvalidRedirectUri() {
            when(queryParamsAuthorizeValidator.validate(any(AuthenticationRequest.class)))
                    .thenThrow(ClientRedirectUriValidationException.class);

            APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
            event.setHttpMethod("GET");
            event.setQueryStringParameters(
                    Map.of(
                            "client_id", "test-id",
                            "redirect_uri", "http://incorrect-redirect-uri",
                            "scope", "email,openid,profile",
                            "response_type", "code",
                            "state", "test-state"));
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            APIGatewayProxyResponseEvent response = makeHandlerRequest(event);

            assertThat(response, hasStatus(400));
            assertThat(response, hasBody("Invalid request"));
        }

        @Test
        void shouldReturn400WhenAuthorisationRequestBodyContainsInvalidScope() {
            when(queryParamsAuthorizeValidator.validate(any(AuthenticationRequest.class)))
                    .thenReturn(
                            Optional.of(
                                    new AuthRequestError(
                                            OAuth2Error.INVALID_SCOPE,
                                            URI.create("http://localhost:8080"),
                                            new State("test-state"))));

            APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
            event.setBody(
                    "client_id=test-id&redirect_uri=http%3A%2F%2Flocalhost%3A8080&scope=email+openid+profile+non-existent-scope&response_type=code&state=test-state");
            event.setHttpMethod("POST");
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            APIGatewayProxyResponseEvent response = makeHandlerRequest(event);

            assertThat(response, hasStatus(302));
            assertEquals(
                    "http://localhost:8080?error=invalid_scope&error_description=Invalid%2C+unknown+or+malformed+scope&state=test-state",
                    response.getHeaders().get(ResponseHeaders.LOCATION));

            verify(auditService)
                    .submitAuditEvent(
                            AUTHORISATION_REQUEST_ERROR,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER,
                            pair("description", OAuth2Error.INVALID_SCOPE.getDescription()));
        }

        @Test
        void shouldReturnBadRequestWhenNoQueryStringParametersArePresent() {
            APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
            event.setHttpMethod("GET");
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            var response = makeHandlerRequest(event);

            verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_REQUEST_ERROR,
                            "",
                            BASE_AUDIT_USER,
                            pair(
                                    "description",
                                    "No parameters are present in the Authentication request query string or body"));

            assertThat(response, hasStatus(400));
            assertThat(response, hasBody(ErrorResponse.ERROR_1001.getMessage()));
        }

        @ParameterizedTest
        @ValueSource(strings = {"PUT", "DELETE", "PATCH"})
        void shouldThrowExceptionWhenMethodIsNotGetOrPost(String method) {
            APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
            event.setHttpMethod(method);
            event.setQueryStringParameters(
                    Map.of(
                            "client_id", "test-id",
                            "redirect_uri", "http://localhost:8080",
                            "scope", "email,openid,profile",
                            "response_type", "code"));
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            RuntimeException expectedException =
                    assertThrows(
                            InvalidHttpMethodException.class,
                            () -> makeHandlerRequest(event),
                            "Expected to throw InvalidHttpMethodException");

            assertThat(
                    expectedException.getMessage(),
                    equalTo(
                            String.format(
                                    "Authentication request does not support %s requests",
                                    method)));
        }

        @Test
        void shouldCallClassifyParseExceptionWhenUnrecognisedPromptValue()
                throws InvalidAuthenticationRequestException,
                        ClientNotFoundException,
                        MissingClientIDException,
                        IncorrectRedirectUriException,
                        MissingRedirectUriException {
            doThrow(
                            new InvalidAuthenticationRequestException(
                                    new com.nimbusds.oauth2.sdk.ParseException(
                                                    "Invalid prompt parameter: Unknown prompt type: unrecognised")
                                            .getErrorObject()))
                    .when(authorisationService)
                    .classifyParseException(any());

            Map<String, String> requestParams =
                    buildRequestParams(Map.of("prompt", "unrecognised"));

            ArgumentCaptor<com.nimbusds.oauth2.sdk.ParseException> parseExceptionArgument =
                    ArgumentCaptor.forClass(com.nimbusds.oauth2.sdk.ParseException.class);

            makeHandlerRequest(withRequestEvent(requestParams));

            verify(authorisationService).classifyParseException(parseExceptionArgument.capture());
            assertEquals(
                    "Invalid prompt parameter: Unknown prompt type: unrecognised",
                    parseExceptionArgument.getValue().getMessage());
        }

        @Test
        void shouldValidateRequestObjectWhenJARValidationIsRequired()
                throws JOSEException, JwksException, ClientSignatureValidationException {
            when(orchestrationAuthorizationService.isJarValidationRequired(any())).thenReturn(true);
            var event = new APIGatewayProxyRequestEvent();
            var jwtClaimsSet = buildjwtClaimsSet("https://localhost/authorize", null, null);
            event.setQueryStringParameters(
                    Map.of(
                            "client_id",
                            CLIENT_ID.getValue(),
                            "scope",
                            "openid",
                            "response_type",
                            "code",
                            "request",
                            generateSignedJWT(jwtClaimsSet, RSA_KEY_PAIR).serialize()));
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            event.setHttpMethod("GET");
            makeHandlerRequest(event);
            verify(requestObjectAuthorizeValidator).validate(any());
        }

        @Test
        void shouldValidateRequestObjectWhenJARValidationIsNotRequired()
                throws JOSEException, JwksException, ClientSignatureValidationException {
            when(orchestrationAuthorizationService.isJarValidationRequired(any()))
                    .thenReturn(false);
            var event = new APIGatewayProxyRequestEvent();
            var jwtClaimsSet = buildjwtClaimsSet("https://localhost/authorize", null, null);
            event.setQueryStringParameters(
                    Map.of(
                            "client_id",
                            CLIENT_ID.getValue(),
                            "scope",
                            "openid",
                            "response_type",
                            "code",
                            "request",
                            generateSignedJWT(jwtClaimsSet, RSA_KEY_PAIR).serialize()));
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            event.setHttpMethod("GET");
            makeHandlerRequest(event);
            verify(requestObjectAuthorizeValidator).validate(any());
        }

        @Test
        void
                shouldRedirectToProvidedRedirectUriWhenJARIsRequiredButRequestObjectIsMissingAndRedirectUriIsInClientRegistry() {
            when(orchestrationAuthorizationService.isJarValidationRequired(any())).thenReturn(true);
            var event = new APIGatewayProxyRequestEvent();
            event.setQueryStringParameters(
                    Map.of(
                            "client_id",
                            CLIENT_ID.getValue(),
                            "scope",
                            SCOPE,
                            "redirect_uri",
                            REDIRECT_URI,
                            "response_type",
                            "code"));
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            event.setHttpMethod("GET");
            var response = makeHandlerRequest(event);

            assertThat(response.getStatusCode(), equalTo(302));
            assertThat(
                    response.getHeaders().get(ResponseHeaders.LOCATION),
                    equalTo(
                            "https://localhost:8080?error=access_denied&error_description=JAR+required+for+client+but+request+does+not+contain+Request+Object"));

            assertThat(
                    logging.events(),
                    hasItems(
                            withMessage(
                                    "JAR required for client but request does not contain Request Object"),
                            withMessage("Redirecting")));
        }

        @Test
        void
                shouldThrowBadRequestWhenJARIsRequiredButRequestObjectIsMissingAndRedirectUriIsNotInClientRegistry() {
            when(orchestrationAuthorizationService.isJarValidationRequired(any())).thenReturn(true);
            var event = new APIGatewayProxyRequestEvent();
            event.setQueryStringParameters(
                    Map.of(
                            "client_id",
                            CLIENT_ID.getValue(),
                            "scope",
                            SCOPE,
                            "redirect_uri",
                            "invalid-redirect-uri",
                            "response_type",
                            "code"));
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            event.setHttpMethod("GET");
            var response = makeHandlerRequest(event);

            assertThat(response.getStatusCode(), equalTo(400));
            assertThat(response.getBody(), equalTo(INVALID_REQUEST.getDescription()));

            assertThat(
                    logging.events(),
                    hasItems(
                            withMessage(
                                    "JAR required for client but request does not contain Request Object"),
                            withMessage(
                                    "Redirect URI invalid-redirect-uri is invalid for client")));
        }

        @Test
        void shouldRedirectToRPWhenClientIsNotActive() {
            when(clientService.getClient(CLIENT_ID.toString()))
                    .thenReturn(Optional.of(generateClientRegistry().withActive(false)));

            var event = new APIGatewayProxyRequestEvent();
            event.setQueryStringParameters(
                    Map.of(
                            "client_id",
                            CLIENT_ID.getValue(),
                            "scope",
                            SCOPE,
                            "redirect_uri",
                            REDIRECT_URI,
                            "response_type",
                            "code"));
            event.setHttpMethod("GET");
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            var response = makeHandlerRequest(event);

            assertThat(response, hasStatus(302));
            assertThat(
                    logging.events(),
                    hasItem(withMessage("Client configured as not active in Client Registry")));
            assertThat(
                    response.getHeaders().get(ResponseHeaders.LOCATION),
                    equalTo(
                            REDIRECT_URI
                                    + "?error=unauthorized_client&error_description=client+deactivated"));
        }

        @Test
        void shouldRedirectToLoginWhenRequestObjectIsValid()
                throws JOSEException, JwksException, ClientSignatureValidationException {
            when(requestObjectAuthorizeValidator.validate(any(AuthenticationRequest.class)))
                    .thenReturn(Optional.empty());
            var event = new APIGatewayProxyRequestEvent();
            var jwtClaimsSet = buildjwtClaimsSet("https://localhost/authorize", null, null);
            event.setQueryStringParameters(
                    Map.of(
                            "client_id",
                            CLIENT_ID.getValue(),
                            "scope",
                            "openid",
                            "response_type",
                            "code",
                            "request",
                            generateSignedJWT(jwtClaimsSet, RSA_KEY_PAIR).serialize()));
            event.setHttpMethod("GET");
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            var response = makeHandlerRequest(event);

            assertThat(response, hasStatus(302));
            var uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

            assertEquals(FRONT_END_BASE_URI.getAuthority(), uri.getAuthority());
            assertTrue(
                    response.getMultiValueHeaders()
                            .get(ResponseHeaders.SET_COOKIE)
                            .contains(EXPECTED_SESSION_COOKIE_STRING));
            var diPersistentCookieString =
                    response.getMultiValueHeaders().get(ResponseHeaders.SET_COOKIE).get(1);
            var sessionId =
                    extractSessionId(
                            diPersistentCookieString, EXPECTED_BASE_PERSISTENT_COOKIE_VALUE);
            assertTrue(isValidPersistentSessionCookieWithDoubleDashedTimestamp(sessionId));
            verify(sessionService).storeOrUpdateSession(session);
            verify(orchSessionService).addSession(any());

            verify(requestObjectAuthorizeValidator).validate(any());

            inOrder.verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER.withSessionId(SESSION_ID),
                            pair("client-name", RP_CLIENT_NAME),
                            pair("new_authentication_required", false));
        }

        @Test
        void shouldRedirectToLoginWhenPostRequestObjectIsValid()
                throws JOSEException, JwksException, ClientSignatureValidationException {
            when(requestObjectAuthorizeValidator.validate(any(AuthenticationRequest.class)))
                    .thenReturn(Optional.empty());
            var event = new APIGatewayProxyRequestEvent();
            event.setHttpMethod("POST");
            var jwtClaimsSet = buildjwtClaimsSet("https://localhost/authorize", null, null);
            event.setBody(
                    String.format(
                            "client_id=%s&scope=openid&response_type=code&request=%s",
                            URLEncoder.encode(CLIENT_ID.getValue(), Charset.defaultCharset()),
                            URLEncoder.encode(
                                    generateSignedJWT(jwtClaimsSet, RSA_KEY_PAIR).serialize(),
                                    Charset.defaultCharset())));

            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            var response = makeHandlerRequest(event);

            assertThat(response, hasStatus(302));
            var uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

            assertEquals(FRONT_END_BASE_URI.getAuthority(), uri.getAuthority());
            assertTrue(
                    response.getMultiValueHeaders()
                            .get(ResponseHeaders.SET_COOKIE)
                            .contains(EXPECTED_SESSION_COOKIE_STRING));
            var diPersistentCookieString =
                    response.getMultiValueHeaders().get(ResponseHeaders.SET_COOKIE).get(1);
            var sessionId =
                    extractSessionId(
                            diPersistentCookieString, EXPECTED_BASE_PERSISTENT_COOKIE_VALUE);
            assertTrue(isValidPersistentSessionCookieWithDoubleDashedTimestamp(sessionId));
            verify(sessionService).storeOrUpdateSession(session);
            verify(orchSessionService).addSession(any());

            inOrder.verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER.withSessionId(SESSION_ID),
                            pair("client-name", RP_CLIENT_NAME),
                            pair("new_authentication_required", false));
        }

        @Test
        void shouldRedirectToRPWhenRequestObjectIsNotValid()
                throws JOSEException, JwksException, ClientSignatureValidationException {
            when(requestObjectAuthorizeValidator.validate(any(AuthenticationRequest.class)))
                    .thenReturn(
                            Optional.of(
                                    new AuthRequestError(
                                            OAuth2Error.INVALID_SCOPE,
                                            URI.create("http://localhost:8080"),
                                            new State("test-state"))));
            var event = new APIGatewayProxyRequestEvent();
            var jwtClaimsSet = buildjwtClaimsSet("https://localhost/authorize", null, null);
            event.setQueryStringParameters(
                    Map.of(
                            "client_id",
                            CLIENT_ID.getValue(),
                            "scope",
                            "openid",
                            "response_type",
                            "code",
                            "request",
                            generateSignedJWT(jwtClaimsSet, RSA_KEY_PAIR).serialize()));
            event.setHttpMethod("GET");
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            var response = makeHandlerRequest(event);

            assertThat(response, hasStatus(302));
            assertEquals(
                    "http://localhost:8080?error=invalid_scope&error_description=Invalid%2C+unknown+or+malformed+scope&state=test-state",
                    response.getHeaders().get(ResponseHeaders.LOCATION));
        }

        @Test
        void shouldRedirectToRPWhenPostRequestObjectIsNotValid()
                throws JOSEException, JwksException, ClientSignatureValidationException {
            when(requestObjectAuthorizeValidator.validate(any(AuthenticationRequest.class)))
                    .thenReturn(
                            Optional.of(
                                    new AuthRequestError(
                                            OAuth2Error.INVALID_SCOPE,
                                            URI.create("http://localhost:8080"),
                                            new State("test-state"))));
            var event = new APIGatewayProxyRequestEvent();
            event.setHttpMethod("POST");
            var jwtClaimsSet = buildjwtClaimsSet("https://localhost/authorize", null, null);
            event.setBody(
                    String.format(
                            "client_id=%s&scope=openid&response_type=code&request=%s",
                            URLEncoder.encode(CLIENT_ID.getValue(), Charset.defaultCharset()),
                            URLEncoder.encode(
                                    generateSignedJWT(jwtClaimsSet, RSA_KEY_PAIR).serialize(),
                                    Charset.defaultCharset())));

            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            var response = makeHandlerRequest(event);

            assertThat(response, hasStatus(302));
            assertEquals(
                    "http://localhost:8080?error=invalid_scope&error_description=Invalid%2C+unknown+or+malformed+scope&state=test-state",
                    response.getHeaders().get(ResponseHeaders.LOCATION));
        }

        @Test
        void shouldReturnValidationFailedWhenSignatureIsInvalid()
                throws JOSEException, JwksException, ClientSignatureValidationException {
            when(requestObjectAuthorizeValidator.validate(any()))
                    .thenThrow(ClientSignatureValidationException.class);

            var event = new APIGatewayProxyRequestEvent();
            var jwtClaimsSet = buildjwtClaimsSet("https://localhost/authorize", null, null);
            event.setQueryStringParameters(
                    Map.of(
                            "client_id",
                            CLIENT_ID.getValue(),
                            "scope",
                            "openid",
                            "response_type",
                            "code",
                            "request",
                            generateSignedJWT(jwtClaimsSet, RSA_KEY_PAIR).serialize()));
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            event.setHttpMethod("GET");
            var response = makeHandlerRequest(event);
            assertEquals(400, response.getStatusCode());
            assertEquals("Trust chain validation failed", response.getBody());
        }

        @Test
        void shouldRedirectToLoginWhenMissingNonce()
                throws JOSEException, JwksException, ClientSignatureValidationException {
            when(requestObjectAuthorizeValidator.validate(any(AuthenticationRequest.class)))
                    .thenReturn(Optional.empty());
            var event = new APIGatewayProxyRequestEvent();
            var jwtClaimsSet =
                    new JWTClaimsSet.Builder()
                            .audience("https://localhost/authorize")
                            .claim("redirect_uri", REDIRECT_URI)
                            .claim("response_type", ResponseType.CODE.toString())
                            .claim("scope", SCOPE)
                            .claim("state", STATE.getValue())
                            .claim("client_id", CLIENT_ID.getValue())
                            .claim("claims", CLAIMS)
                            .issuer(CLIENT_ID.getValue())
                            .build();

            event.setQueryStringParameters(
                    Map.of(
                            "client_id",
                            CLIENT_ID.getValue(),
                            "scope",
                            "openid",
                            "response_type",
                            "code",
                            "request",
                            generateSignedJWT(jwtClaimsSet, RSA_KEY_PAIR).serialize()));
            event.setHttpMethod("GET");
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            var response = makeHandlerRequest(event);

            assertThat(response, hasStatus(302));
            var uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

            assertEquals(FRONT_END_BASE_URI.getAuthority(), uri.getAuthority());
            assertTrue(
                    response.getMultiValueHeaders()
                            .get(ResponseHeaders.SET_COOKIE)
                            .contains(EXPECTED_SESSION_COOKIE_STRING));
            var diPersistentCookieString =
                    response.getMultiValueHeaders().get(ResponseHeaders.SET_COOKIE).get(1);
            var sessionId =
                    extractSessionId(
                            diPersistentCookieString, EXPECTED_BASE_PERSISTENT_COOKIE_VALUE);
            assertTrue(isValidPersistentSessionCookieWithDoubleDashedTimestamp(sessionId));
            verify(sessionService).storeOrUpdateSession(session);
            verify(orchSessionService).addSession(any());

            verify(requestObjectAuthorizeValidator).validate(any());

            inOrder.verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER.withSessionId(SESSION_ID),
                            pair("client-name", RP_CLIENT_NAME),
                            pair("new_authentication_required", false));
        }

        @Test
        void shouldReturnServerErrorOnJwksException()
                throws JOSEException, JwksException, ClientSignatureValidationException {
            when(requestObjectAuthorizeValidator.validate(any())).thenThrow(JwksException.class);

            var event = new APIGatewayProxyRequestEvent();
            var jwtClaimsSet = buildjwtClaimsSet("https://localhost/authorize", null, null);
            event.setQueryStringParameters(
                    Map.of(
                            "client_id",
                            CLIENT_ID.getValue(),
                            "scope",
                            "openid",
                            "response_type",
                            "code",
                            "request",
                            generateSignedJWT(jwtClaimsSet, RSA_KEY_PAIR).serialize()));
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            event.setHttpMethod("GET");
            var response = makeHandlerRequest(event);
            assertEquals(500, response.getStatusCode());
            assertEquals("Unexpected server error", response.getBody());
        }

        @Test
        void shouldAuditRequestParsedWhenRpSidPresent() {
            var rpSid = "test-rp-sid";
            Map<String, String> requestParams = buildRequestParams(Map.of("rp_sid", rpSid));
            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            makeHandlerRequest(event);
            verifyAuthorisationRequestParsedAuditEvent(rpSid, false, false);
        }

        @Test
        void shouldAuditRequestParsedWhenRpSidNotPresent() {
            Map<String, String> requestParams = buildRequestParams(null);
            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            makeHandlerRequest(event);

            verifyAuthorisationRequestParsedAuditEvent(AuditService.UNKNOWN, false, false);
        }

        @Test
        void shouldAuditRequestParsedWhenOnAuthOnlyFlow() {
            Map<String, String> requestParams = buildRequestParams(Map.of("vtr", "[\"Cl.Cm\"]"));
            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            makeHandlerRequest(event);

            verifyAuthorisationRequestParsedAuditEvent(AuditService.UNKNOWN, false, false);
        }

        @Test
        void shouldAuditRequestParsedWhenOnIdentityFlow() {
            Map<String, String> requestParams = buildRequestParams(Map.of("vtr", "[\"P2.Cl.Cm\"]"));
            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            makeHandlerRequest(event);

            verifyAuthorisationRequestParsedAuditEvent(AuditService.UNKNOWN, true, false);
        }

        @Test
        void shouldNotAddReauthenticateOrPreviousJourneyIdClaimForQueryParameters() {
            Map<String, String> requestParams =
                    buildRequestParams(
                            Map.of(
                                    "prompt",
                                    Prompt.Type.LOGIN.toString(),
                                    "id_token_hint",
                                    SERIALIZED_SIGNED_ID_TOKEN));
            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            APIGatewayProxyResponseEvent response = makeHandlerRequest(event);

            URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

            verifyAuthorisationRequestParsedAuditEvent(AuditService.UNKNOWN, false, false);
            assertThat(uri.getQuery(), not(containsString("reauthenticate")));
            assertThat(uri.getQuery(), not(containsString("previous_govuk_signin_journey_id")));
        }

        @Test
        void
                shouldNotAddReauthenticateOrPreviousJourneyIdClaimForQueryParametersWithAuthOrchSplitEnabled() {
            Map<String, String> requestParams =
                    buildRequestParams(
                            Map.of(
                                    "prompt",
                                    Prompt.Type.LOGIN.toString(),
                                    "id_token_hint",
                                    SERIALIZED_SIGNED_ID_TOKEN));
            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            makeHandlerRequest(event);

            verifyAuthorisationRequestParsedAuditEvent(AuditService.UNKNOWN, false, false);

            ArgumentCaptor<JWTClaimsSet> argument = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(argument.capture());
            assertNull(argument.getValue().getClaim("reauthenticate"));
            assertNull(argument.getValue().getClaim("previous_govuk_signin_journey_id"));
        }

        @Test
        void shouldAddReauthenticateAndPreviousJourneyIdClaimIfPromptIsLoginAndIdTokenIsValid()
                throws JOSEException, ParseException {
            when(tokenValidationService.isTokenSignatureValid(any())).thenReturn(true);

            var jwtClaimsSet =
                    buildjwtClaimsSet(
                            ID_TOKEN_AUDIENCE,
                            Prompt.Type.LOGIN.toString(),
                            SERIALIZED_SIGNED_ID_TOKEN);

            Map<String, String> requestParams =
                    buildRequestParams(
                            Map.of(
                                    "client_id",
                                    CLIENT_ID.getValue(),
                                    "response_type",
                                    "code",
                                    "scope",
                                    "openid",
                                    "request",
                                    generateSignedJWT(jwtClaimsSet, RSA_KEY_PAIR).serialize()));

            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            makeHandlerRequest(event);

            verifyAuthorisationRequestParsedAuditEvent(AuditService.UNKNOWN, false, true);

            ArgumentCaptor<JWTClaimsSet> argument = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(argument.capture());
            assertThat(
                    argument.getValue().getStringClaim("reauthenticate"),
                    equalTo(SUBJECT.getValue()));
            assertThat(
                    argument.getValue().getStringClaim("previous_govuk_signin_journey_id"),
                    equalTo(CLIENT_SESSION_ID));
        }

        @Test
        void shouldAddPreviousSessionIdClaimIfThereIsAnExistingSession() throws ParseException {
            when(sessionService.getSessionFromSessionCookie(any()))
                    .thenReturn(Optional.of(new Session(SESSION_ID)));

            var requestParams =
                    buildRequestParams(
                            Map.of("scope", "openid profile phone", "vtr", "[\"Cl.Cm.P2\"]"));

            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            makeHandlerRequest(event);

            ArgumentCaptor<JWTClaimsSet> argument = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(argument.capture());
            assertThat(
                    argument.getValue().getStringClaim("previous_session_id"), equalTo(SESSION_ID));
        }

        @Test
        void shouldAddPublicSubjectIdClaimIfAmScopePresent() throws ParseException {
            Map<String, String> requestParams = buildRequestParams(Map.of("scope", "openid am"));
            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            makeHandlerRequest(event);

            verifyAuthorisationRequestParsedAuditEvent(AuditService.UNKNOWN, false, false);
            ArgumentCaptor<JWTClaimsSet> argument = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(argument.capture());

            var expectedClaim = "{\"userinfo\":{\"public_subject_id\":null}}";
            var actualClaim = argument.getValue().getStringClaim("claim");
            assertThat(actualClaim, is(equalTo(expectedClaim)));
        }

        @Test
        void shouldAddLegacySubjectIdClaimIfGovUkAccountScopePresent() throws ParseException {
            Map<String, String> requestParams =
                    buildRequestParams(Map.of("scope", "openid govuk-account"));
            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            makeHandlerRequest(event);

            verifyAuthorisationRequestParsedAuditEvent(AuditService.UNKNOWN, false, false);
            ArgumentCaptor<JWTClaimsSet> argument = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(argument.capture());

            var expectedClaim = "{\"userinfo\":{\"legacy_subject_id\":null}}";
            var actualClaim = argument.getValue().getStringClaim("claim");
            assertThat(actualClaim, is(equalTo(expectedClaim)));
        }

        private static Stream<Prompt.Type> prompts() {
            return Stream.of(Prompt.Type.CREATE, null);
        }

        @ParameterizedTest
        @MethodSource("prompts")
        void shouldNotAddReauthenticateOrPreviousJourneyIdClaimIfPromptIsNotLoginAndIdTokenIsValid(
                Prompt.Type prompt) throws JOSEException {
            when(tokenValidationService.isTokenSignatureValid(any())).thenReturn(true);

            var jwtClaimsSet =
                    buildjwtClaimsSet(
                            ID_TOKEN_AUDIENCE,
                            prompt == null ? null : prompt.toString(),
                            SERIALIZED_SIGNED_ID_TOKEN);

            Map<String, String> requestParams =
                    buildRequestParams(
                            Map.of(
                                    "client_id",
                                    CLIENT_ID.getValue(),
                                    "response_type",
                                    "code",
                                    "scope",
                                    "openid",
                                    "request",
                                    generateSignedJWT(jwtClaimsSet, RSA_KEY_PAIR).serialize()));

            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            makeHandlerRequest(event);

            verifyAuthorisationRequestParsedAuditEvent(AuditService.UNKNOWN, false, false);

            ArgumentCaptor<JWTClaimsSet> argument = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(argument.capture());
            assertNull(argument.getValue().getClaim("reauthenticate"));
            assertNull(argument.getValue().getClaim("previous_govuk_signin_journey_id"));
        }

        @Test
        void shouldNotAddReauthenticateOrPreviousJourneyIdClaimIfIdTokenHintIsNotPresent()
                throws JOSEException {
            var jwtClaimsSet =
                    buildjwtClaimsSet(ID_TOKEN_AUDIENCE, Prompt.Type.LOGIN.toString(), null);

            Map<String, String> requestParams =
                    buildRequestParams(
                            Map.of(
                                    "client_id",
                                    CLIENT_ID.getValue(),
                                    "response_type",
                                    "code",
                                    "scope",
                                    "openid",
                                    "request",
                                    generateSignedJWT(jwtClaimsSet, RSA_KEY_PAIR).serialize()));

            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            makeHandlerRequest(event);

            verifyAuthorisationRequestParsedAuditEvent(AuditService.UNKNOWN, false, false);

            ArgumentCaptor<JWTClaimsSet> argument = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(argument.capture());
            assertNull(argument.getValue().getClaim("reauthenticate"));
            assertNull(argument.getValue().getClaim("previous_govuk_signin_journey_id"));
        }

        @Test
        void shouldGetVtrFromIdTokenIfNotPresentInAuthenticationRequestAndReauthRequested()
                throws JOSEException {
            when(tokenValidationService.isTokenSignatureValid(any())).thenReturn(true);
            var serialisedIdTokenHint =
                    TokenGeneratorHelper.generateIDToken(
                                    CLIENT_ID.getValue(),
                                    SUBJECT,
                                    "http://localhost-rp",
                                    EC_SIGNING_KEY,
                                    "[PCL200.Cl.Cm]")
                            .serialize();
            var jwtClaimsSet =
                    buildjwtClaimsSet(
                            ID_TOKEN_AUDIENCE, Prompt.Type.LOGIN.toString(), serialisedIdTokenHint);
            Map<String, String> requestParams =
                    buildRequestParams(
                            Map.of(
                                    "client_id",
                                    CLIENT_ID.getValue(),
                                    "response_type",
                                    "code",
                                    "scope",
                                    "openid",
                                    "request",
                                    generateSignedJWT(jwtClaimsSet, RSA_KEY_PAIR).serialize()));

            APIGatewayProxyResponseEvent response =
                    makeHandlerRequest(withRequestEvent(requestParams));
            assertThat(response.getStatusCode(), equalTo(302));

            ArgumentCaptor<JWTClaimsSet> argument = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(argument.capture());
            assertThat(argument.getValue().getClaim("confidence"), equalTo("Cl.Cm"));
        }

        @Test
        void shouldSetTheRelevantCookiesInTheHeader() {
            Session sessionWithBrowserSessionId =
                    new Session(SESSION_ID).withBrowserSessionId(BROWSER_SESSION_ID);
            when(sessionService.generateSession()).thenReturn(sessionWithBrowserSessionId);

            Map<String, String> requestParams = buildRequestParams(null);
            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            APIGatewayProxyResponseEvent response = makeHandlerRequest(event);

            assertTrue(
                    response.getMultiValueHeaders()
                            .get(ResponseHeaders.SET_COOKIE)
                            .get(0)
                            .contains(EXPECTED_SESSION_COOKIE_STRING));
            assertTrue(
                    response.getMultiValueHeaders()
                            .get(ResponseHeaders.SET_COOKIE)
                            .get(1)
                            .contains(EXPECTED_PERSISTENT_COOKIE_VALUE_WITH_TIMESTAMP));
            assertTrue(
                    response.getMultiValueHeaders()
                            .get(ResponseHeaders.SET_COOKIE)
                            .get(2)
                            .contains(
                                    format(
                                            "%s=%s; Domain=oidc.auth.ida.digital.cabinet-office.gov.uk; Secure; HttpOnly;",
                                            BROWSER_SESSION_ID_COOKIE_NAME, BROWSER_SESSION_ID)));
        }

        @Test
        void shouldErrorIfIdTokenIsInvalid() throws JOSEException {
            when(tokenValidationService.isTokenSignatureValid(any())).thenReturn(false);

            var jwtClaimsSet =
                    buildjwtClaimsSet(
                            ID_TOKEN_AUDIENCE,
                            Prompt.Type.LOGIN.toString(),
                            SERIALIZED_SIGNED_ID_TOKEN);

            Map<String, String> requestParams =
                    buildRequestParams(
                            Map.of(
                                    "client_id",
                                    CLIENT_ID.getValue(),
                                    "response_type",
                                    "code",
                                    "scope",
                                    "openid",
                                    "request",
                                    generateSignedJWT(jwtClaimsSet, RSA_KEY_PAIR).serialize()));

            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            APIGatewayProxyResponseEvent response = makeHandlerRequest(event);

            var expectedErrorObject =
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE, "Unable to validate id_token_hint");
            var expectedURI =
                    new AuthenticationErrorResponse(
                                    URI.create("https://localhost:8080"),
                                    expectedErrorObject,
                                    STATE,
                                    null)
                            .toURI()
                            .toString();
            assertThat(response, hasStatus(302));
            assertEquals(expectedURI, response.getHeaders().get(ResponseHeaders.LOCATION));

            verifyAuthorisationRequestParsedAuditEvent(AuditService.UNKNOWN, false, true);
            inOrder.verify(auditService)
                    .submitAuditEvent(
                            AUTHORISATION_REQUEST_ERROR,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER.withSessionId(SESSION_ID),
                            pair("description", expectedErrorObject.getDescription()));
        }

        @Test
        void shouldErrorIfIdTokenHasIncorrectClient() throws JOSEException {
            when(tokenValidationService.isTokenSignatureValid(any())).thenReturn(true);

            var signedIDTokenIncorrectClient =
                    TokenGeneratorHelper.generateIDToken(
                            "not-the-client-id", SUBJECT, "http://localhost-rp", EC_SIGNING_KEY);

            var jwtClaimsSet =
                    buildjwtClaimsSet(
                            ID_TOKEN_AUDIENCE,
                            Prompt.Type.LOGIN.toString(),
                            signedIDTokenIncorrectClient.serialize());

            Map<String, String> requestParams =
                    buildRequestParams(
                            Map.of(
                                    "client_id",
                                    CLIENT_ID.getValue(),
                                    "response_type",
                                    "code",
                                    "scope",
                                    "openid",
                                    "request",
                                    generateSignedJWT(jwtClaimsSet, RSA_KEY_PAIR).serialize()));

            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            APIGatewayProxyResponseEvent response = makeHandlerRequest(event);

            var expectedErrorObject =
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE, "Invalid id_token_hint for client");
            var expectedURI =
                    new AuthenticationErrorResponse(
                                    URI.create("https://localhost:8080"),
                                    expectedErrorObject,
                                    STATE,
                                    null)
                            .toURI()
                            .toString();
            assertThat(response, hasStatus(302));
            assertEquals(expectedURI, response.getHeaders().get(ResponseHeaders.LOCATION));

            verifyAuthorisationRequestParsedAuditEvent(AuditService.UNKNOWN, false, true);

            inOrder.verify(auditService)
                    .submitAuditEvent(
                            AUTHORISATION_REQUEST_ERROR,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER.withSessionId(SESSION_ID),
                            pair("description", expectedErrorObject.getDescription()));
        }

        @Nested
        class BrowserSessionId {
            @Test
            void shouldCreateNewSessionWithNewBSIDWhenNeitherSessionNorBSIDCookiePresent() {
                ArgumentCaptor<Session> sessionCaptor = ArgumentCaptor.forClass(Session.class);
                APIGatewayProxyResponseEvent response =
                        setupExistingSessionAndCookieInHeader(null, null);

                verify(sessionService).generateSession();
                verify(sessionService).storeOrUpdateSession(sessionCaptor.capture());
                assertEquals(
                        NEW_BROWSER_SESSION_ID, sessionCaptor.getValue().getBrowserSessionId());
                assertEquals(
                        format(
                                "%s=%s; Domain=oidc.auth.ida.digital.cabinet-office.gov.uk; Secure; HttpOnly;",
                                BROWSER_SESSION_ID_COOKIE_NAME, NEW_BROWSER_SESSION_ID),
                        browserSessionIdCookieFromResponse(response));
                inOrder.verify(auditService)
                        .submitAuditEvent(
                                OidcAuditableEvent.AUTHORISATION_INITIATED,
                                CLIENT_ID.getValue(),
                                BASE_AUDIT_USER.withSessionId(NEW_SESSION_ID),
                                pair("client-name", RP_CLIENT_NAME),
                                pair("new_authentication_required", false));
            }

            @Test
            void shouldCreateNewSessionWithNewBSIDWhenNoSessionButCookieBSIDPresent() {
                ArgumentCaptor<Session> sessionCaptor = ArgumentCaptor.forClass(Session.class);
                APIGatewayProxyResponseEvent response =
                        setupExistingSessionAndCookieInHeader(null, BROWSER_SESSION_ID);

                verify(sessionService).generateSession();
                verify(sessionService).storeOrUpdateSession(sessionCaptor.capture());
                assertEquals(
                        NEW_BROWSER_SESSION_ID, sessionCaptor.getValue().getBrowserSessionId());
                assertEquals(
                        format(
                                "%s=%s; Domain=oidc.auth.ida.digital.cabinet-office.gov.uk; Secure; HttpOnly;",
                                BROWSER_SESSION_ID_COOKIE_NAME, NEW_BROWSER_SESSION_ID),
                        browserSessionIdCookieFromResponse(response));
                inOrder.verify(auditService)
                        .submitAuditEvent(
                                OidcAuditableEvent.AUTHORISATION_INITIATED,
                                CLIENT_ID.getValue(),
                                BASE_AUDIT_USER.withSessionId(NEW_SESSION_ID),
                                pair("client-name", RP_CLIENT_NAME),
                                pair("new_authentication_required", false));
            }

            @Test
            void shouldCreateNewSessionWhenSessionHasBSIDButCookieDoesNot() {
                ArgumentCaptor<Session> sessionCaptor = ArgumentCaptor.forClass(Session.class);
                APIGatewayProxyResponseEvent response =
                        setupExistingSessionAndCookieInHeader(
                                new Session(SESSION_ID).withBrowserSessionId(BROWSER_SESSION_ID),
                                null);

                verify(sessionService).generateSession();
                verify(sessionService).storeOrUpdateSession(sessionCaptor.capture());
                assertEquals(
                        NEW_BROWSER_SESSION_ID, sessionCaptor.getValue().getBrowserSessionId());
                assertEquals(
                        format(
                                "%s=%s; Domain=oidc.auth.ida.digital.cabinet-office.gov.uk; Secure; HttpOnly;",
                                BROWSER_SESSION_ID_COOKIE_NAME, NEW_BROWSER_SESSION_ID),
                        browserSessionIdCookieFromResponse(response));
                inOrder.verify(auditService)
                        .submitAuditEvent(
                                OidcAuditableEvent.AUTHORISATION_INITIATED,
                                CLIENT_ID.getValue(),
                                BASE_AUDIT_USER.withSessionId(NEW_SESSION_ID),
                                pair("client-name", RP_CLIENT_NAME),
                                pair("new_authentication_required", true));
            }

            @Test
            void shouldUseExistingSessionWithNoBSIDEvenWhenBSIDCookiePresent() {
                ArgumentCaptor<Session> sessionCaptor = ArgumentCaptor.forClass(Session.class);
                APIGatewayProxyResponseEvent response =
                        setupExistingSessionAndCookieInHeader(
                                new Session(SESSION_ID).withBrowserSessionId(null),
                                BROWSER_SESSION_ID);

                verify(sessionService, never()).generateSession();
                verify(sessionService).storeOrUpdateSession(sessionCaptor.capture());
                assertNull(sessionCaptor.getValue().getBrowserSessionId());
                assertEquals(
                        2, response.getMultiValueHeaders().get(ResponseHeaders.SET_COOKIE).size());
                assertTrue(
                        response.getMultiValueHeaders().get(ResponseHeaders.SET_COOKIE).stream()
                                .noneMatch(
                                        it ->
                                                it.startsWith(
                                                        format(
                                                                "%s=",
                                                                BROWSER_SESSION_ID_COOKIE_NAME))));
                inOrder.verify(auditService)
                        .submitAuditEvent(
                                OidcAuditableEvent.AUTHORISATION_INITIATED,
                                CLIENT_ID.getValue(),
                                BASE_AUDIT_USER.withSessionId(SESSION_ID),
                                pair("client-name", RP_CLIENT_NAME),
                                pair("new_authentication_required", false));
            }

            @Test
            void shouldUseExistingSessionWhenBSIDsMatch() {
                ArgumentCaptor<Session> sessionCaptor = ArgumentCaptor.forClass(Session.class);
                APIGatewayProxyResponseEvent response =
                        setupExistingSessionAndCookieInHeader(
                                new Session(SESSION_ID).withBrowserSessionId(BROWSER_SESSION_ID),
                                BROWSER_SESSION_ID);

                verify(sessionService, never()).generateSession();
                verify(sessionService).storeOrUpdateSession(sessionCaptor.capture());
                assertEquals(BROWSER_SESSION_ID, sessionCaptor.getValue().getBrowserSessionId());
                assertEquals(
                        format(
                                "%s=%s; Domain=oidc.auth.ida.digital.cabinet-office.gov.uk; Secure; HttpOnly;",
                                BROWSER_SESSION_ID_COOKIE_NAME, BROWSER_SESSION_ID),
                        browserSessionIdCookieFromResponse(response));
                inOrder.verify(auditService)
                        .submitAuditEvent(
                                OidcAuditableEvent.AUTHORISATION_INITIATED,
                                CLIENT_ID.getValue(),
                                BASE_AUDIT_USER.withSessionId(SESSION_ID),
                                pair("client-name", RP_CLIENT_NAME),
                                pair("new_authentication_required", false));
            }

            @Test
            void shouldCreateNewSessionWhenSessionAndCookieBSIDDoNotMatch() {
                ArgumentCaptor<Session> sessionCaptor = ArgumentCaptor.forClass(Session.class);
                APIGatewayProxyResponseEvent response =
                        setupExistingSessionAndCookieInHeader(
                                new Session(SESSION_ID).withBrowserSessionId(BROWSER_SESSION_ID),
                                DIFFERENT_BROWSER_SESSION_ID);

                verify(sessionService).generateSession();
                verify(sessionService).storeOrUpdateSession(sessionCaptor.capture());
                assertEquals(
                        NEW_BROWSER_SESSION_ID, sessionCaptor.getValue().getBrowserSessionId());
                assertEquals(
                        format(
                                "%s=%s; Domain=oidc.auth.ida.digital.cabinet-office.gov.uk; Secure; HttpOnly;",
                                BROWSER_SESSION_ID_COOKIE_NAME, NEW_BROWSER_SESSION_ID),
                        browserSessionIdCookieFromResponse(response));
                inOrder.verify(auditService)
                        .submitAuditEvent(
                                OidcAuditableEvent.AUTHORISATION_INITIATED,
                                CLIENT_ID.getValue(),
                                BASE_AUDIT_USER.withSessionId(NEW_SESSION_ID),
                                pair("client-name", RP_CLIENT_NAME),
                                pair("new_authentication_required", true));
            }

            private APIGatewayProxyResponseEvent setupExistingSessionAndCookieInHeader(
                    Session existingSession, String browserSessionIdFromCookie) {
                when(sessionService.getSessionFromSessionCookie(any()))
                        .thenReturn(Optional.ofNullable(existingSession));
                when(sessionService.generateSession())
                        .thenReturn(
                                new Session(NEW_SESSION_ID)
                                        .withBrowserSessionId(NEW_BROWSER_SESSION_ID));

                Map<String, String> requestParams = buildRequestParams(null);
                APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);
                event.setRequestContext(
                        new ProxyRequestContext()
                                .withIdentity(
                                        new RequestIdentity().withSourceIp("123.123.123.123")));
                if (browserSessionIdFromCookie != null) {
                    event.setHeaders(
                            Map.of(
                                    "Cookie",
                                    format(
                                            "%s=%s",
                                            BROWSER_SESSION_ID_COOKIE_NAME,
                                            browserSessionIdFromCookie)));
                }

                return makeHandlerRequest(event);
            }
        }
    }

    @Nested
    class DocAppJourney {
        MockedStatic<DocAppSubjectIdHelper> docAppSubjectIdHelperMock;
        EncryptedJWT encryptedJwt;

        @BeforeEach()
        void docAppSetup() throws ParseException, JOSEException {

            var clientRegistry = generateClientRegistry().withClientType(ClientType.APP.getValue());

            when(clientService.getClient(CLIENT_ID.getValue()))
                    .thenReturn(Optional.of(clientRegistry));

            docAppSubjectIdHelperMock = mockStatic(DocAppSubjectIdHelper.class);

            var uri = URI.create("someUri");
            when(configService.getDocAppDomain()).thenReturn(uri);
            when(DocAppSubjectIdHelper.calculateDocAppSubjectId(any(), anyBoolean(), any()))
                    .thenReturn(new Subject("calculatedSubjectId"));
            when(configService.getDocAppAuthorisationClientId()).thenReturn(CLIENT_ID.getValue());
            when(configService.getDocAppAuthorisationURI())
                    .thenReturn(URI.create(DOC_APP_REDIRECT_URI));
            encryptedJwt = createEncryptedJWT();
            when(docAppAuthorisationService.constructRequestJWT(any(), any(), any(), any()))
                    .thenReturn(encryptedJwt);
        }

        @AfterEach()
        void docAppTearDown() {
            docAppSubjectIdHelperMock.close();
        }

        @Test
        void shouldCreateANewClientSessionAndAttachItToExistingSessionWhenRequestIsDocAppRequest()
                throws JOSEException {
            var sessionSpy = spy(session);
            when(sessionService.getSessionFromSessionCookie(any()))
                    .thenReturn(Optional.of(sessionSpy));
            makeDocAppHandlerRequest();
            verify(sessionSpy).addClientSession(CLIENT_SESSION_ID);
        }

        @Test
        void shouldSaveStateAndStoreItToClientSession() throws JOSEException {
            makeDocAppHandlerRequest();
            verify(docAppAuthorisationService).storeState(eq(SESSION_ID), any());
            verify(noSessionOrchestrationService)
                    .storeClientSessionIdAgainstState(eq(CLIENT_SESSION_ID), any());
        }

        @Test
        void shouldUpdateOrchSessionWhenThereIsAnExistingSession() throws JOSEException {
            withExistingSession(session);

            makeDocAppHandlerRequest();

            verify(orchSessionService)
                    .addOrUpdateSessionId(
                            Optional.of(orchSession.getSessionId()), session.getSessionId());
            verify(orchSessionService).updateSession(orchSession);
        }

        @Test
        void shouldSetTheRelevantCookiesInTheHeader() throws JOSEException {
            var response = makeDocAppHandlerRequest();

            verify(orchSessionService).addSession(any());
            assertTrue(
                    response.getMultiValueHeaders()
                            .get(ResponseHeaders.SET_COOKIE)
                            .contains(EXPECTED_SESSION_COOKIE_STRING));
            assertTrue(
                    response.getMultiValueHeaders()
                            .get(ResponseHeaders.SET_COOKIE)
                            .get(1)
                            .contains(EXPECTED_PERSISTENT_COOKIE_VALUE_WITH_TIMESTAMP));
        }

        @Test
        void shouldRedirectToTheDocAppRedirectUriWithEncryptedJwtWhenTheRequestIsADocAppRequest()
                throws JOSEException {

            var response = makeDocAppHandlerRequest();

            verify(clientSessionService).storeClientSession(anyString(), any());
            verify(orchSessionService).addSession(any());

            assertThat(response, hasStatus(302));
            assertThat(
                    response.getHeaders().get("Location"),
                    equalTo(
                            DOC_APP_REDIRECT_URI
                                    + "?response_type=code&request="
                                    + encryptedJwt.serialize()
                                    + "&client_id="
                                    + CLIENT_ID.getValue()));

            verify(cloudwatchMetricsService).incrementCounter(eq("DocAppHandoff"), any());

            verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_REQUEST_RECEIVED, "", BASE_AUDIT_USER);
            verify(auditService)
                    .submitAuditEvent(
                            DocAppAuditableEvent.DOC_APP_AUTHORISATION_REQUESTED,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER
                                    .withSessionId(SESSION_ID)
                                    .withUserId("test-subject-id"));
        }
    }

    @Test
    void returns400ForOpenRedirect()
            throws InvalidAuthenticationRequestException,
                    ClientNotFoundException,
                    MissingClientIDException,
                    IncorrectRedirectUriException,
                    MissingRedirectUriException {
        doThrow(new IncorrectRedirectUriException(OAuth2Error.INVALID_REQUEST))
                .when(authorisationService)
                .classifyParseException(any());

        var response =
                makeHandlerRequest(
                        withRequestEvent(
                                Map.of(
                                        "redirect_uri",
                                        "https://www.example.com",
                                        "client_id",
                                        "invalid-client")));

        assertThat(response, hasStatus(400));
        assertThat(response, hasBody(OAuth2Error.INVALID_REQUEST.getDescription()));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        "invalid-client",
                        BASE_AUDIT_USER,
                        pair("description", OAuth2Error.INVALID_REQUEST.getDescription()));
    }

    private static Stream<ErrorObject> expectedErrorObjects() {
        return Stream.of(
                OAuth2Error.UNSUPPORTED_RESPONSE_TYPE,
                OAuth2Error.INVALID_SCOPE,
                OAuth2Error.UNAUTHORIZED_CLIENT,
                OAuth2Error.INVALID_REQUEST);
    }

    @ParameterizedTest
    @MethodSource("expectedErrorObjects")
    void shouldReturnErrorWhenRequestObjectIsInvalid(ErrorObject errorObject)
            throws JwksException, ClientSignatureValidationException {
        when(orchestrationAuthorizationService.isJarValidationRequired(any())).thenReturn(true);
        when(requestObjectAuthorizeValidator.validate(any(AuthenticationRequest.class)))
                .thenReturn(
                        Optional.of(
                                new AuthRequestError(
                                        errorObject, URI.create("http://localhost:8080"), null)));
        var event = new APIGatewayProxyRequestEvent();
        event.setHttpMethod("GET");
        event.setQueryStringParameters(
                Map.of(
                        "client_id", "test-id",
                        "scope", "openid",
                        "response_type", "code",
                        "request", new PlainJWT(new JWTClaimsSet.Builder().build()).serialize()));
        event.setRequestContext(
                new ProxyRequestContext()
                        .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
        event.withHeaders(Map.of("txma-audit-encoded", TXMA_ENCODED_HEADER_VALUE));
        var response = makeHandlerRequest(event);

        var expectedURI =
                new AuthenticationErrorResponse(
                                URI.create("http://localhost:8080"), errorObject, null, null)
                        .toURI()
                        .toString();
        assertThat(response, hasStatus(302));
        assertEquals(expectedURI, response.getHeaders().get(ResponseHeaders.LOCATION));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        CLIENT_ID.getValue(),
                        BASE_AUDIT_USER,
                        pair("description", errorObject.getDescription()));
    }

    @Test
    void shouldReturnErrorWhenInvalidPromptValuesArePassed() {
        Map<String, String> requestParams = buildRequestParams(Map.of("prompt", "select_account"));
        APIGatewayProxyResponseEvent response = makeHandlerRequest(withRequestEvent(requestParams));
        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                containsString(OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS.getCode()));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        CLIENT_ID.getValue(),
                        BASE_AUDIT_USER,
                        pair(
                                "description",
                                OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS.getDescription()));
    }

    @Test
    void shouldReturnBadRequestWhenMissingClientId()
            throws InvalidAuthenticationRequestException,
                    ClientNotFoundException,
                    MissingClientIDException,
                    IncorrectRedirectUriException,
                    MissingRedirectUriException {
        doThrow(new MissingClientIDException(OAuth2Error.INVALID_REQUEST))
                .when(authorisationService)
                .classifyParseException(any());

        var response = makeHandlerRequest(withRequestEvent(Map.of()));

        assertThat(response, hasStatus(400));
        assertThat(response, hasBody(ErrorResponse.ERROR_1001.getMessage()));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        "",
                        BASE_AUDIT_USER,
                        pair("description", INVALID_REQUEST.getDescription()));
    }

    @Test
    void shouldReturnBadRequestWhenMissingRedirectUri()
            throws InvalidAuthenticationRequestException,
                    ClientNotFoundException,
                    MissingClientIDException,
                    IncorrectRedirectUriException,
                    MissingRedirectUriException {
        doThrow(new MissingRedirectUriException(OAuth2Error.INVALID_REQUEST))
                .when(authorisationService)
                .classifyParseException(any());

        var response =
                makeHandlerRequest(withRequestEvent(Map.of("client_id", CLIENT_ID.getValue())));

        assertThat(response, hasStatus(400));
        assertThat(response, hasBody(ErrorResponse.ERROR_1001.getMessage()));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        CLIENT_ID.getValue(),
                        BASE_AUDIT_USER,
                        pair("description", INVALID_REQUEST.getDescription()));
    }

    @Test
    void shouldReturnBadRequestWhenIncorrectRedirectUri()
            throws InvalidAuthenticationRequestException,
                    ClientNotFoundException,
                    MissingClientIDException,
                    IncorrectRedirectUriException,
                    MissingRedirectUriException {
        doThrow(new IncorrectRedirectUriException(OAuth2Error.INVALID_REQUEST))
                .when(authorisationService)
                .classifyParseException(any());

        var response =
                makeHandlerRequest(
                        withRequestEvent(
                                Map.of(
                                        "client_id",
                                        CLIENT_ID.getValue(),
                                        "redirect_uri",
                                        "bad_redirect_uri")));

        assertThat(response, hasStatus(400));
        assertThat(response, hasBody(INVALID_REQUEST.getDescription()));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        CLIENT_ID.getValue(),
                        BASE_AUDIT_USER,
                        pair("description", INVALID_REQUEST.getDescription()));
    }

    @Test
    void shouldReturnBadRequestWhenClientNotFound()
            throws InvalidAuthenticationRequestException,
                    ClientNotFoundException,
                    MissingClientIDException,
                    IncorrectRedirectUriException,
                    MissingRedirectUriException {
        doThrow(new ClientNotFoundException(CLIENT_ID.getValue()))
                .when(authorisationService)
                .classifyParseException(any());

        var response =
                makeHandlerRequest(
                        withRequestEvent(
                                Map.of(
                                        "client_id",
                                        CLIENT_ID.getValue(),
                                        "redirect_uri",
                                        REDIRECT_URI)));

        assertThat(response, hasStatus(400));
        assertThat(response, hasBody(INVALID_REQUEST.getDescription()));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        CLIENT_ID.getValue(),
                        BASE_AUDIT_USER,
                        pair(
                                "description",
                                format("No Client found for ClientID: %s", CLIENT_ID.getValue())));
    }

    @Test
    void shouldReturnRedirectWithErrorWhenInvalidAuthParameters()
            throws InvalidAuthenticationRequestException,
                    ClientNotFoundException,
                    MissingClientIDException,
                    IncorrectRedirectUriException,
                    MissingRedirectUriException {
        doThrow(new InvalidAuthenticationRequestException(INVALID_REQUEST))
                .when(authorisationService)
                .classifyParseException(any());

        var response =
                makeHandlerRequest(
                        withRequestEvent(
                                Map.of(
                                        "client_id",
                                        CLIENT_ID.getValue(),
                                        "redirect_uri",
                                        REDIRECT_URI,
                                        "prompt",
                                        "invalid-prompt")));

        assertThat(response, hasStatus(302));
        assertEquals(
                "https://localhost:8080?error=invalid_request&error_description=Invalid+request",
                response.getHeaders().get(ResponseHeaders.LOCATION));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        CLIENT_ID.getValue(),
                        BASE_AUDIT_USER,
                        pair("description", INVALID_REQUEST.getDescription()));
    }

    private APIGatewayProxyResponseEvent makeHandlerRequest(APIGatewayProxyRequestEvent event) {
        var response = handler.handleRequest(event, context);

        inOrder.verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.AUTHORISATION_REQUEST_RECEIVED, "", BASE_AUDIT_USER);

        LogEvent logEvent = logging.events().get(0);

        assertThat(
                logEvent,
                hasContextData(
                        "persistentSessionId", EXPECTED_PERSISTENT_COOKIE_VALUE_WITH_TIMESTAMP));
        assertThat(logEvent, hasContextData("awsRequestId", AWS_REQUEST_ID));

        return response;
    }

    private APIGatewayProxyResponseEvent makeDocAppHandlerRequest() throws JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience("oidc-audience")
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("state", STATE)
                        .claim("nonce", NONCE.getValue())
                        .claim("scope", "openid doc-checking-app")
                        .claim("claims", CLAIMS)
                        .issuer(CLIENT_ID.getValue())
                        .build();

        Map<String, String> requestParams =
                buildRequestParams(
                        Map.of(
                                "client_id",
                                CLIENT_ID.getValue(),
                                "response_type",
                                "code",
                                "scope",
                                "openid",
                                "request",
                                generateSignedJWT(jwtClaimsSet, RSA_KEY_PAIR).serialize()));

        return makeHandlerRequest(withRequestEvent(requestParams));
    }

    private APIGatewayProxyRequestEvent withRequestEvent(Map<String, String> requestParams) {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHttpMethod("GET");
        event.setQueryStringParameters(requestParams);
        event.setRequestContext(
                new ProxyRequestContext()
                        .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
        event.withHeaders(Map.of("txma-audit-encoded", TXMA_ENCODED_HEADER_VALUE));
        return event;
    }

    private Map<String, String> buildRequestParams(Map<String, String> extraParams) {
        Map<String, String> requestParams = new HashMap<>();
        requestParams.put("client_id", CLIENT_ID.getValue());
        requestParams.put("redirect_uri", REDIRECT_URI);
        requestParams.put("scope", SCOPE);
        requestParams.put("response_type", RESPONSE_TYPE);
        requestParams.put("state", STATE.getValue());

        if (extraParams != null && !extraParams.isEmpty()) {
            requestParams.putAll(extraParams);
        }
        return requestParams;
    }

    private AuthenticationRequest generateAuthRequest(Optional<String> credentialTrustLevel) {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        AuthenticationRequest.Builder builder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE, scope, CLIENT_ID, URI.create(REDIRECT_URI))
                        .state(STATE)
                        .nonce(new Nonce());
        credentialTrustLevel.ifPresent(t -> builder.customParameter("vtr", t));
        return builder.build();
    }

    private void withExistingSession(Session session) {
        when(sessionService.getSessionFromSessionCookie(any())).thenReturn(Optional.of(session));
        when(orchSessionService.getSessionFromSessionCookie(any()))
                .thenReturn(Optional.of(orchSession));
        when(orchSessionService.addOrUpdateSessionId(any(), any())).thenReturn(orchSession);
    }

    private void withNoSession() {
        when(sessionService.getSessionFromSessionCookie(any())).thenReturn(Optional.empty());
        when(orchSessionService.getSessionFromSessionCookie(any())).thenReturn(Optional.empty());
    }

    private ClientRegistry generateClientRegistry() {
        return new ClientRegistry()
                .withClientID("test-id")
                .withCookieConsentShared(IS_COOKIE_CONSENT_SHARED)
                .withClientName(RP_CLIENT_NAME)
                .withSectorIdentifierUri("https://test.com")
                .withRedirectUrls(List.of(REDIRECT_URI))
                .withOneLoginService(IS_ONE_LOGIN)
                .withServiceType(RP_SERVICE_TYPE)
                .withSubjectType("public")
                .withIdentityVerificationSupported(true);
    }

    private static EncryptedJWT createEncryptedJWT() throws JOSEException, ParseException {
        var ecdsaSigner = new ECDSASigner(EC_SIGNING_KEY);
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .claim("client-name", RP_CLIENT_NAME)
                        .claim("cookie-consent-shared", IS_COOKIE_CONSENT_SHARED)
                        .claim("is-one-login-service", IS_ONE_LOGIN)
                        .claim("service-type", RP_SERVICE_TYPE)
                        .claim("state", STATE)
                        .claim("scopes", SCOPE)
                        .claim("redirect-uri", REDIRECT_URI)
                        .build();
        var jwsHeader = new JWSHeader(JWSAlgorithm.ES256);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        signedJWT.sign(ecdsaSigner);
        var rsaEncryptionKey =
                new RSAKeyGenerator(2048).keyID("encryption-key-id").generate().toRSAPublicKey();
        var jweObject =
                new JWEObject(
                        new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                                .contentType("JWT")
                                .build(),
                        new Payload(signedJWT));
        jweObject.encrypt(new RSAEncrypter(rsaEncryptionKey));
        return EncryptedJWT.parse(jweObject.serialize());
    }

    public static Map<String, String> splitQuery(String stringUrl) {
        var uri = URI.create(stringUrl);
        Map<String, String> query_pairs = new LinkedHashMap<>();
        var query = uri.getQuery();
        var pairs = query.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            query_pairs.put(
                    URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8));
        }
        return query_pairs;
    }

    private static void verifyAuditEvents(
            List<AuditableEvent> auditEvents, AuditService auditService) {
        for (AuditableEvent event : auditEvents) {
            verify(auditService).submitAuditEvent(eq(event), any(), eq(BASE_AUDIT_USER));
        }
    }

    private static String extractSessionId(String input, String sessionIdPrefix) {
        String sessionIdPattern = sessionIdPrefix + "--[0-9]+";
        var pattern = Pattern.compile(sessionIdPattern);
        var matcher = pattern.matcher(input);

        if (matcher.find()) {
            return matcher.group();
        } else {
            return "";
        }
    }

    private static JWTClaimsSet buildjwtClaimsSet(String audience, String prompt, String idToken) {
        return new JWTClaimsSet.Builder()
                .audience(audience)
                .claim("prompt", prompt)
                .claim("id_token_hint", idToken)
                .claim("redirect_uri", REDIRECT_URI)
                .claim("response_type", ResponseType.CODE.toString())
                .claim("scope", SCOPE)
                .claim("state", STATE.getValue())
                .claim("nonce", null)
                .claim("client_id", CLIENT_ID.getValue())
                .claim("claims", CLAIMS)
                .issuer(CLIENT_ID.getValue())
                .build();
    }

    private void verifyAuthorisationRequestParsedAuditEvent(
            String rpSid, boolean identityRequested, boolean reauthRequested) {
        inOrder.verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.AUTHORISATION_REQUEST_PARSED,
                        CLIENT_ID.getValue(),
                        BASE_AUDIT_USER,
                        pair("rpSid", rpSid),
                        pair("identityRequested", identityRequested),
                        pair("reauthRequested", reauthRequested));
    }

    private static ECKey generateECSigningKey() {
        try {
            return new ECKeyGenerator(Curve.P_256)
                    .keyID("key-id")
                    .algorithm(JWSAlgorithm.ES256)
                    .generate();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    private static String getIdTokenAudience() {
        try {
            return SignedJWT.parse(AuthorisationHandlerTest.SERIALIZED_SIGNED_ID_TOKEN)
                    .getJWTClaimsSet()
                    .getAudience()
                    .stream()
                    .findFirst()
                    .orElse(null);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    private String browserSessionIdCookieFromResponse(APIGatewayProxyResponseEvent response) {
        return response.getMultiValueHeaders().get(ResponseHeaders.SET_COOKIE).stream()
                .filter(it -> it.startsWith(format("%s=", BROWSER_SESSION_ID_COOKIE_NAME)))
                .findAny()
                .orElseThrow();
    }
}
