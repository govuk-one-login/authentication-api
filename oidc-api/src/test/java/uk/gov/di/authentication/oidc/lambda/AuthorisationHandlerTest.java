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
import org.apache.logging.log4j.core.LogEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InOrder;
import org.mockito.MockedStatic;
import uk.gov.di.authentication.app.domain.DocAppAuditableEvent;
import uk.gov.di.authentication.oidc.domain.OidcAuditableEvent;
import uk.gov.di.authentication.oidc.entity.AuthRequestError;
import uk.gov.di.authentication.oidc.exceptions.InvalidHttpMethodException;
import uk.gov.di.authentication.oidc.services.OrchestrationAuthorizationService;
import uk.gov.di.authentication.oidc.validators.QueryParamsAuthorizeValidator;
import uk.gov.di.authentication.oidc.validators.RequestObjectAuthorizeValidator;
import uk.gov.di.orchestration.shared.domain.AuditableEvent;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.helpers.DocAppSubjectIdHelper;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.ClientService;
import uk.gov.di.orchestration.shared.services.ClientSessionService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DocAppAuthorisationService;
import uk.gov.di.orchestration.shared.services.NoSessionOrchestrationService;
import uk.gov.di.orchestration.shared.services.SessionService;
import uk.gov.di.orchestration.shared.state.UserContext;
import uk.gov.di.orchestration.sharedtest.helper.KeyPairHelper;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
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

    private final NoSessionOrchestrationService noSessionOrchestrationService =
            mock(NoSessionOrchestrationService.class);
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
    private static final URI LOGIN_URL = URI.create("https://example.com");
    private static final String AWS_REQUEST_ID = "aws-request-id";
    private static final ClientID CLIENT_ID = new ClientID("test-id");
    private static final String SESSION_ID = "a-session-id";
    private static final String REDIRECT_URI = "https://localhost:8080";
    private static final String DOC_APP_REDIRECT_URI = "/doc-app-authorisation";
    private static final String SCOPE = "email openid profile";
    private static final String RESPONSE_TYPE = "code";
    private static final String TEST_ORCHESTRATOR_CLIENT_ID = "test-orch-client-id";
    private static final String RP_CLIENT_NAME = "test-rp-client-name";
    private static final EncryptedJWT TEST_ENCRYPTED_JWT;
    private static final Boolean IS_ONE_LOGIN = false;
    private static final Boolean IS_COOKIE_CONSENT_SHARED = false;
    private static final Boolean IS_CONSENT_REQUIRED = true;
    private static final String RP_SERVICE_TYPE = "MANDATORY";

    static {
        try {
            TEST_ENCRYPTED_JWT = createEncryptedJWT();
        } catch (JOSEException | ParseException e) {
            throw new RuntimeException(e);
        }
    }

    private Session session;
    private static final String CLIENT_SESSION_ID = "client-session-id";
    private static final State STATE = new State();
    private static final Nonce NONCE = new Nonce();

    private AuthorisationHandler handler;

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(AuthorisationHandler.class);

    @BeforeEach
    public void setUp() {
        when(configService.getEnvironment()).thenReturn("test-env");
        when(configService.getDomainName()).thenReturn("auth.ida.digital.cabinet-office.gov.uk");
        when(configService.getLoginURI()).thenReturn(LOGIN_URL);
        when(configService.getOrchestrationClientId()).thenReturn(TEST_ORCHESTRATOR_CLIENT_ID);
        when(configService.getSessionCookieAttributes()).thenReturn("Secure; HttpOnly;");
        when(configService.getSessionCookieMaxAge()).thenReturn(3600);
        when(configService.getPersistentCookieMaxAge()).thenReturn(34190000);
        when(queryParamsAuthorizeValidator.validate(any(AuthenticationRequest.class)))
                .thenReturn(Optional.empty());
        when(orchestrationAuthorizationService.getExistingOrCreateNewPersistentSessionId(any()))
                .thenReturn(EXPECTED_PERSISTENT_COOKIE_VALUE_WITH_TIMESTAMP);
        when(orchestrationAuthorizationService.getEffectiveVectorOfTrust(any()))
                .thenReturn(new VectorOfTrust(CredentialTrustLevel.MEDIUM_LEVEL));
        when(userContext.getClient()).thenReturn(Optional.of(generateClientRegistry()));
        when(context.getAwsRequestId()).thenReturn(AWS_REQUEST_ID);
        handler =
                new AuthorisationHandler(
                        configService,
                        sessionService,
                        clientSessionService,
                        orchestrationAuthorizationService,
                        auditService,
                        queryParamsAuthorizeValidator,
                        requestObjectAuthorizeValidator,
                        clientService,
                        docAppAuthorisationService,
                        cloudwatchMetricsService,
                        noSessionOrchestrationService);
        session = new Session("a-session-id");
        when(sessionService.createSession()).thenReturn(session);
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
            assertEquals(LOGIN_URL.getAuthority(), uri.getAuthority());
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
            verify(sessionService).save(eq(session));
            verify(clientSessionService).storeClientSession(CLIENT_SESSION_ID, clientSession);

            inOrder.verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_SESSION_ID,
                            session.getSessionId(),
                            CLIENT_ID.getValue(),
                            AuditService.UNKNOWN,
                            AuditService.UNKNOWN,
                            "123.123.123.123",
                            AuditService.UNKNOWN,
                            EXPECTED_PERSISTENT_COOKIE_VALUE_WITH_TIMESTAMP,
                            pair("client-name", RP_CLIENT_NAME));
        }

        @Test
        void
                shouldRedirectToLoginWhenUserHasNoExistingSessionWithSignedAndEncryptedJwtInBodyWhenAuthOrchSplitFeatureFlagEnabled() {
            var orchClientId = "orchestration-client-id";
            when(configService.isAuthOrchSplitEnabled()).thenReturn(true);
            when(configService.getOrchestrationClientId()).thenReturn(orchClientId);
            when(orchestrationAuthorizationService.getSignedAndEncryptedJWT(any()))
                    .thenReturn(TEST_ENCRYPTED_JWT);

            var requestParams = buildRequestParams(null);
            var event = withRequestEvent(requestParams);
            when(orchestrationAuthorizationService.getSignedAndEncryptedJWT(any()))
                    .thenReturn(TEST_ENCRYPTED_JWT);
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
            assertEquals(LOGIN_URL.getAuthority(), uri.getAuthority());
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

            verify(sessionService).save(session);
            verify(clientSessionService).storeClientSession(CLIENT_SESSION_ID, clientSession);

            inOrder.verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_SESSION_ID,
                            session.getSessionId(),
                            CLIENT_ID.getValue(),
                            AuditService.UNKNOWN,
                            AuditService.UNKNOWN,
                            "123.123.123.123",
                            AuditService.UNKNOWN,
                            EXPECTED_PERSISTENT_COOKIE_VALUE_WITH_TIMESTAMP,
                            pair("client-name", RP_CLIENT_NAME));
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
            assertEquals(LOGIN_URL.getAuthority(), uri.getAuthority());
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

            verify(sessionService).save(eq(session));
            verify(clientSessionService).storeClientSession(CLIENT_SESSION_ID, clientSession);

            inOrder.verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_SESSION_ID,
                            session.getSessionId(),
                            CLIENT_ID.getValue(),
                            AuditService.UNKNOWN,
                            AuditService.UNKNOWN,
                            "123.123.123.123",
                            AuditService.UNKNOWN,
                            EXPECTED_PERSISTENT_COOKIE_VALUE_WITH_TIMESTAMP,
                            pair("client-name", RP_CLIENT_NAME));
        }

        @ParameterizedTest
        @ValueSource(booleans = {true, false})
        void shouldRetainGoogleAnalyticsParamThroughRedirectToLoginWhenClientIsFaceToFaceRp(
                boolean isAuthOrchSplitEnabled) {
            when(configService.isAuthOrchSplitEnabled()).thenReturn(isAuthOrchSplitEnabled);

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
            assertEquals(LOGIN_URL.getAuthority(), uri.getAuthority());
            assertThat(uri.getQuery(), containsString("result=sign-in"));
            assertThat(
                    uri.getQuery(), not(containsString("an-irrelevant-key=an-irrelevant-value")));
        }

        @Test
        void shouldRedirectToLoginWhenUserNeedsToBeUplifted() {
            session.setCurrentCredentialStrength(CredentialTrustLevel.LOW_LEVEL);
            withExistingSession(session);
            when(clientSession.getEffectiveVectorOfTrust()).thenReturn(VectorOfTrust.getDefaults());
            when(userContext.getClientSession()).thenReturn(clientSession);
            when(userContext.getSession()).thenReturn(session);
            when(clientSession.getAuthRequestParams())
                    .thenReturn(
                            generateAuthRequest(Optional.of(jsonArrayOf("Cl.Cm"))).toParameters());

            APIGatewayProxyResponseEvent response =
                    makeHandlerRequest(withRequestEvent(buildRequestParams(Map.of("vtr", "Cl"))));
            URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

            assertThat(response, hasStatus(302));
            assertEquals(LOGIN_URL.getAuthority(), uri.getAuthority());

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

            verify(sessionService).save(eq(session));
            verify(clientSessionService).storeClientSession(CLIENT_SESSION_ID, clientSession);

            inOrder.verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_SESSION_ID,
                            session.getSessionId(),
                            CLIENT_ID.getValue(),
                            AuditService.UNKNOWN,
                            AuditService.UNKNOWN,
                            "123.123.123.123",
                            AuditService.UNKNOWN,
                            EXPECTED_PERSISTENT_COOKIE_VALUE_WITH_TIMESTAMP,
                            pair("client-name", RP_CLIENT_NAME));
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
                            withRequestEvent(buildRequestParams(Map.of("vtr", "P2.Cl.Cm"))));
            URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

            assertThat(response, hasStatus(302));
            assertEquals(LOGIN_URL.getAuthority(), uri.getAuthority());

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

            verify(sessionService).save(eq(session));
            verify(clientSessionService).storeClientSession(CLIENT_SESSION_ID, clientSession);

            inOrder.verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_SESSION_ID,
                            session.getSessionId(),
                            CLIENT_ID.getValue(),
                            AuditService.UNKNOWN,
                            AuditService.UNKNOWN,
                            "123.123.123.123",
                            AuditService.UNKNOWN,
                            EXPECTED_PERSISTENT_COOKIE_VALUE_WITH_TIMESTAMP,
                            pair("client-name", RP_CLIENT_NAME));
        }

        @Test
        void shouldThrowErrorWhenClientIsNotPresent() {
            when(clientService.getClient(CLIENT_ID.getValue())).thenReturn(Optional.empty());

            assertThrows(
                    RuntimeException.class,
                    () -> makeDocAppHandlerRequest(),
                    format("No Client found for ClientID: %s", CLIENT_ID.getValue()));
            verifyNoInteractions(configService);
            verifyNoInteractions(requestObjectAuthorizeValidator);
        }

        @Test
        void shouldThrowErrorWhenAuthorisationRequestCannotBeParsed() {
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

            assertThrows(
                    RuntimeException.class,
                    () -> makeHandlerRequest(event),
                    "Invalid request: Missing response_type parameter");

            verify(auditService)
                    .submitAuditEvent(
                            AUTHORISATION_REQUEST_ERROR,
                            CLIENT_SESSION_ID,
                            "",
                            "",
                            "",
                            "",
                            "123.123.123.123",
                            "",
                            EXPECTED_PERSISTENT_COOKIE_VALUE_WITH_TIMESTAMP,
                            pair(
                                    "description",
                                    "Invalid request: Missing response_type parameter"));
        }

        @Test
        void shouldReturn400WhenAuthorisationRequestContainsInvalidScope() {
            when(queryParamsAuthorizeValidator.validate(any(AuthenticationRequest.class)))
                    .thenReturn(
                            Optional.of(
                                    new AuthRequestError(
                                            OAuth2Error.INVALID_SCOPE,
                                            URI.create("http://localhost:8080"))));

            APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
            event.setHttpMethod("GET");
            event.setQueryStringParameters(
                    Map.of(
                            "client_id", "test-id",
                            "redirect_uri", "http://localhost:8080",
                            "scope", "email,openid,profile,non-existent-scope",
                            "response_type", "code"));
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));

            APIGatewayProxyResponseEvent response = makeHandlerRequest(event);

            assertThat(response, hasStatus(302));
            assertEquals(
                    "http://localhost:8080?error=invalid_scope&error_description=Invalid%2C+unknown+or+malformed+scope",
                    response.getHeaders().get(ResponseHeaders.LOCATION));

            verify(auditService)
                    .submitAuditEvent(
                            AUTHORISATION_REQUEST_ERROR,
                            CLIENT_SESSION_ID,
                            "",
                            CLIENT_ID.getValue(),
                            "",
                            "",
                            "123.123.123.123",
                            "",
                            EXPECTED_PERSISTENT_COOKIE_VALUE_WITH_TIMESTAMP,
                            pair("description", OAuth2Error.INVALID_SCOPE.getDescription()));
        }

        @Test
        void shouldReturn400WhenAuthorisationRequestBodyContainsInvalidScope() {
            when(queryParamsAuthorizeValidator.validate(any(AuthenticationRequest.class)))
                    .thenReturn(
                            Optional.of(
                                    new AuthRequestError(
                                            OAuth2Error.INVALID_SCOPE,
                                            URI.create("http://localhost:8080"))));

            APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
            event.setBody(
                    "client_id=test-id&redirect_uri=http%3A%2F%2Flocalhost%3A8080&scope=email+openid+profile+non-existent-scope&response_type=code");
            event.setHttpMethod("POST");
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));

            APIGatewayProxyResponseEvent response = makeHandlerRequest(event);

            assertThat(response, hasStatus(302));
            assertEquals(
                    "http://localhost:8080?error=invalid_scope&error_description=Invalid%2C+unknown+or+malformed+scope",
                    response.getHeaders().get(ResponseHeaders.LOCATION));

            verify(auditService)
                    .submitAuditEvent(
                            AUTHORISATION_REQUEST_ERROR,
                            CLIENT_SESSION_ID,
                            "",
                            CLIENT_ID.getValue(),
                            "",
                            "",
                            "123.123.123.123",
                            "",
                            EXPECTED_PERSISTENT_COOKIE_VALUE_WITH_TIMESTAMP,
                            pair("description", OAuth2Error.INVALID_SCOPE.getDescription()));
        }

        @Test
        void shouldThrowExceptionWhenNoQueryStringParametersArePresent() {
            APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
            event.setHttpMethod("GET");
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));

            RuntimeException expectedException =
                    assertThrows(
                            RuntimeException.class,
                            () -> makeHandlerRequest(event),
                            "Expected to throw AccessTokenException");

            assertThat(
                    expectedException.getMessage(),
                    equalTo(
                            "No parameters are present in the Authentication request query string or body"));
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
        void shouldThrowErrorWhenUnrecognisedPromptValue() {
            Map<String, String> requestParams =
                    buildRequestParams(Map.of("prompt", "unrecognised"));

            assertThrows(
                    RuntimeException.class,
                    () -> {
                        makeHandlerRequest(withRequestEvent(requestParams));
                    },
                    "Invalid request: Invalid prompt parameter: Unknown prompt type: unrecognised");

            verify(auditService)
                    .submitAuditEvent(
                            AUTHORISATION_REQUEST_ERROR,
                            CLIENT_SESSION_ID,
                            "",
                            "",
                            "",
                            "",
                            "123.123.123.123",
                            "",
                            EXPECTED_PERSISTENT_COOKIE_VALUE_WITH_TIMESTAMP,
                            pair(
                                    "description",
                                    "Invalid request: Invalid prompt parameter: Unknown prompt type: unrecognised"));
        }

        @Test
        void shouldValidateRequestObjectWhenJARValidationIsRequired() throws JOSEException {
            when(orchestrationAuthorizationService.isJarValidationRequired(any())).thenReturn(true);
            var keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
            var event = new APIGatewayProxyRequestEvent();
            var jwtClaimsSet = buildjwtClaimsSet();
            event.setQueryStringParameters(
                    Map.of(
                            "client_id",
                            CLIENT_ID.getValue(),
                            "scope",
                            "openid",
                            "response_type",
                            "code",
                            "request",
                            generateSignedJWT(jwtClaimsSet, keyPair).serialize()));
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            event.setHttpMethod("GET");

            makeHandlerRequest(event);
            verify(requestObjectAuthorizeValidator).validate(any());
        }

        @Test
        void shouldValidateRequestObjectWhenJARValidationIsNotRequired() throws JOSEException {
            when(orchestrationAuthorizationService.isJarValidationRequired(any()))
                    .thenReturn(false);
            var keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
            var event = new APIGatewayProxyRequestEvent();
            var jwtClaimsSet = buildjwtClaimsSet();
            event.setQueryStringParameters(
                    Map.of(
                            "client_id",
                            CLIENT_ID.getValue(),
                            "scope",
                            "openid",
                            "response_type",
                            "code",
                            "request",
                            generateSignedJWT(jwtClaimsSet, keyPair).serialize()));
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            event.setHttpMethod("GET");

            makeHandlerRequest(event);
            verify(requestObjectAuthorizeValidator).validate(any());
        }

        @Test
        void shouldThrowErrorWhenJARIsRequiredButRequestObjectIsMissing() {
            when(orchestrationAuthorizationService.isJarValidationRequired(any())).thenReturn(true);
            var event = new APIGatewayProxyRequestEvent();
            event.setQueryStringParameters(
                    Map.of(
                            "client_id",
                            CLIENT_ID.getValue(),
                            "scope",
                            SCOPE,
                            "redirect_uri",
                            "some-redirect-uri",
                            "response_type",
                            "code"));
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
            event.setHttpMethod("GET");

            RuntimeException expectedException =
                    assertThrows(
                            RuntimeException.class,
                            () -> makeHandlerRequest(event),
                            "Expected to throw AccessTokenException");

            assertThat(
                    expectedException.getMessage(),
                    equalTo("JAR required for client but request does not contain Request Object"));
        }

        @Test
        void shouldRedirectToLoginWhenRequestObjectIsValid() throws JOSEException {
            var keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
            when(requestObjectAuthorizeValidator.validate(any(AuthenticationRequest.class)))
                    .thenReturn(Optional.empty());
            var event = new APIGatewayProxyRequestEvent();
            var jwtClaimsSet = buildjwtClaimsSet();
            event.setQueryStringParameters(
                    Map.of(
                            "client_id",
                            CLIENT_ID.getValue(),
                            "scope",
                            "openid",
                            "response_type",
                            "code",
                            "request",
                            generateSignedJWT(jwtClaimsSet, keyPair).serialize()));
            event.setHttpMethod("GET");
            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));

            var response = makeHandlerRequest(event);

            assertThat(response, hasStatus(302));
            var uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

            assertEquals(LOGIN_URL.getAuthority(), uri.getAuthority());
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
            verify(sessionService).save(session);

            verify(requestObjectAuthorizeValidator).validate(any());

            inOrder.verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_SESSION_ID,
                            session.getSessionId(),
                            CLIENT_ID.getValue(),
                            AuditService.UNKNOWN,
                            AuditService.UNKNOWN,
                            "123.123.123.123",
                            AuditService.UNKNOWN,
                            EXPECTED_PERSISTENT_COOKIE_VALUE_WITH_TIMESTAMP,
                            pair("client-name", RP_CLIENT_NAME));
        }

        @Test
        void shouldRedirectToLoginWhenPostRequestObjectIsValid() throws JOSEException {
            var keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
            when(requestObjectAuthorizeValidator.validate(any(AuthenticationRequest.class)))
                    .thenReturn(Optional.empty());
            var event = new APIGatewayProxyRequestEvent();
            event.setHttpMethod("POST");
            var jwtClaimsSet = buildjwtClaimsSet();
            event.setBody(
                    String.format(
                            "client_id=%s&scope=openid&response_type=code&request=%s",
                            URLEncoder.encode(CLIENT_ID.getValue(), Charset.defaultCharset()),
                            URLEncoder.encode(
                                    generateSignedJWT(jwtClaimsSet, keyPair).serialize(),
                                    Charset.defaultCharset())));

            event.setRequestContext(
                    new ProxyRequestContext()
                            .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));

            var response = makeHandlerRequest(event);

            assertThat(response, hasStatus(302));
            var uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

            assertEquals(LOGIN_URL.getAuthority(), uri.getAuthority());
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
            verify(sessionService).save(session);

            inOrder.verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_SESSION_ID,
                            session.getSessionId(),
                            CLIENT_ID.getValue(),
                            AuditService.UNKNOWN,
                            AuditService.UNKNOWN,
                            "123.123.123.123",
                            AuditService.UNKNOWN,
                            EXPECTED_PERSISTENT_COOKIE_VALUE_WITH_TIMESTAMP,
                            pair("client-name", RP_CLIENT_NAME));
        }
    }

    @Nested
    class DocAppJourney {
        MockedStatic<DocAppSubjectIdHelper> docAppSubjectIdHelperMock;
        EncryptedJWT encryptedJwt;

        @BeforeEach()
        void docAppSetup() throws ParseException, JOSEException {
            when(configService.isDocAppDecoupleEnabled()).thenReturn(true);

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
        void shouldSetTheRelevantCookiesInTheHeader() throws JOSEException {
            var response = makeDocAppHandlerRequest();

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

            verify(clientSessionService).saveClientSession(anyString(), any());

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

            verifyAuditEvents(
                    List.of(
                            OidcAuditableEvent.AUTHORISATION_REQUEST_RECEIVED,
                            DocAppAuditableEvent.DOC_APP_AUTHORISATION_REQUESTED),
                    auditService);
        }

        @Test
        void shouldNotLogWhenTheDocAppDecoupleFeatureFlagIsOffAndTheRequestIsADocAppRequest()
                throws JOSEException {
            when(configService.isDocAppDecoupleEnabled()).thenReturn(false);

            makeDocAppHandlerRequest();

            assertFalse(
                    logging.events().stream()
                            .map(event -> event.getMessage().getFormattedMessage())
                            .toList()
                            .contains("Doc app request received"));
        }
    }

    @Test
    void shouldNotActAsAnOpenRedirector() {
        assertThrows(
                RuntimeException.class,
                () -> {
                    handler.handleRequest(
                            withRequestEvent(
                                    Map.of(
                                            "redirect_uri",
                                            "https://www.example.com",
                                            "client_id",
                                            "invalid-client")),
                            context);
                });
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
    void shouldReturnErrorWhenRequestObjectIsInvalid(ErrorObject errorObject) {
        when(orchestrationAuthorizationService.isJarValidationRequired(any())).thenReturn(true);
        when(requestObjectAuthorizeValidator.validate(any(AuthenticationRequest.class)))
                .thenReturn(
                        Optional.of(
                                new AuthRequestError(
                                        errorObject, URI.create("http://localhost:8080"))));
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
                        CLIENT_SESSION_ID,
                        "",
                        CLIENT_ID.getValue(),
                        "",
                        "",
                        "123.123.123.123",
                        "",
                        EXPECTED_PERSISTENT_COOKIE_VALUE_WITH_TIMESTAMP,
                        pair("description", errorObject.getDescription()));
    }

    private static Stream<Arguments> invalidPromptValues() {
        return Stream.of(
                Arguments.of("login consent", OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS),
                Arguments.of("consent", OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS),
                Arguments.of("select_account", OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS));
    }

    @ParameterizedTest
    @MethodSource("invalidPromptValues")
    void shouldReturnErrorWhenInvalidPromptValuesArePassed(
            String invalidPromptValues, ErrorObject expectedError) {
        Map<String, String> requestParams =
                buildRequestParams(Map.of("prompt", invalidPromptValues));
        APIGatewayProxyResponseEvent response = makeHandlerRequest(withRequestEvent(requestParams));
        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                containsString(expectedError.getCode()));

        verify(auditService)
                .submitAuditEvent(
                        AUTHORISATION_REQUEST_ERROR,
                        CLIENT_SESSION_ID,
                        "",
                        CLIENT_ID.getValue(),
                        "",
                        "",
                        "123.123.123.123",
                        "",
                        EXPECTED_PERSISTENT_COOKIE_VALUE_WITH_TIMESTAMP,
                        pair("description", expectedError.getDescription()));
    }

    private APIGatewayProxyResponseEvent makeHandlerRequest(APIGatewayProxyRequestEvent event) {
        var response = handler.handleRequest(event, context);

        inOrder.verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.AUTHORISATION_REQUEST_RECEIVED,
                        CLIENT_SESSION_ID,
                        "",
                        "",
                        "",
                        "",
                        "123.123.123.123",
                        "",
                        EXPECTED_PERSISTENT_COOKIE_VALUE_WITH_TIMESTAMP);

        LogEvent logEvent = logging.events().get(0);

        assertThat(
                logEvent,
                hasContextData(
                        "persistentSessionId", EXPECTED_PERSISTENT_COOKIE_VALUE_WITH_TIMESTAMP));
        assertThat(logEvent, hasContextData("awsRequestId", AWS_REQUEST_ID));

        return response;
    }

    private APIGatewayProxyResponseEvent makeDocAppHandlerRequest() throws JOSEException {
        var keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();

        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience("oidc-audience")
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("state", STATE)
                        .claim("nonce", NONCE.getValue())
                        .claim("scope", "openid doc-checking-app")
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
                                generateSignedJWT(jwtClaimsSet, keyPair).serialize()));

        return makeHandlerRequest(withRequestEvent(requestParams));
    }

    private APIGatewayProxyRequestEvent withRequestEvent(Map<String, String> requestParams) {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHttpMethod("GET");
        event.setQueryStringParameters(requestParams);
        event.setRequestContext(
                new ProxyRequestContext()
                        .withIdentity(new RequestIdentity().withSourceIp("123.123.123.123")));
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
    }

    private ClientRegistry generateClientRegistry() {
        return new ClientRegistry()
                .withClientID(new ClientID().getValue())
                .withConsentRequired(IS_COOKIE_CONSENT_SHARED)
                .withClientName(RP_CLIENT_NAME)
                .withSectorIdentifierUri("https://test.com")
                .withOneLoginService(IS_ONE_LOGIN)
                .withServiceType(RP_SERVICE_TYPE)
                .withConsentRequired(IS_CONSENT_REQUIRED)
                .withSubjectType("public");
    }

    private static EncryptedJWT createEncryptedJWT() throws JOSEException, ParseException {
        var ecSigningKey =
                new ECKeyGenerator(Curve.P_256)
                        .keyID("key-id")
                        .algorithm(JWSAlgorithm.ES256)
                        .generate();
        var ecdsaSigner = new ECDSASigner(ecSigningKey);
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .claim("client-name", RP_CLIENT_NAME)
                        .claim("cookie-consent-shared", IS_COOKIE_CONSENT_SHARED)
                        .claim("consent-required", IS_CONSENT_REQUIRED)
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
            verify(auditService)
                    .submitAuditEvent(
                            eq(event),
                            eq(CLIENT_SESSION_ID),
                            any(),
                            any(),
                            any(),
                            any(),
                            any(),
                            any(),
                            any());
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

    private static JWTClaimsSet buildjwtClaimsSet() {
        return new JWTClaimsSet.Builder()
                .audience("https://localhost/authorize")
                .claim("redirect_uri", REDIRECT_URI)
                .claim("response_type", ResponseType.CODE.toString())
                .claim("scope", SCOPE)
                .claim("state", STATE.getValue())
                .claim("nonce", NONCE.getValue())
                .claim("client_id", CLIENT_ID.getValue())
                .issuer(CLIENT_ID.getValue())
                .build();
    }
}
