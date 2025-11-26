package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.ProxyRequestContext;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent.RequestIdentity;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.google.gson.GsonBuilder;
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
import org.approvaltests.JsonApprovals;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import uk.gov.di.authentication.app.domain.DocAppAuditableEvent;
import uk.gov.di.authentication.oidc.domain.OidcAuditableEvent;
import uk.gov.di.authentication.oidc.entity.AuthRequestError;
import uk.gov.di.authentication.oidc.entity.ClientRateLimitConfig;
import uk.gov.di.authentication.oidc.entity.RateLimitDecision;
import uk.gov.di.authentication.oidc.exceptions.IncorrectRedirectUriException;
import uk.gov.di.authentication.oidc.exceptions.InvalidAuthenticationRequestException;
import uk.gov.di.authentication.oidc.exceptions.InvalidHttpMethodException;
import uk.gov.di.authentication.oidc.exceptions.MissingClientIDException;
import uk.gov.di.authentication.oidc.exceptions.MissingRedirectUriException;
import uk.gov.di.authentication.oidc.services.AuthorisationService;
import uk.gov.di.authentication.oidc.services.OrchestrationAuthorizationService;
import uk.gov.di.authentication.oidc.services.RateLimitService;
import uk.gov.di.authentication.oidc.validators.QueryParamsAuthorizeValidator;
import uk.gov.di.authentication.oidc.validators.RequestObjectAuthorizeValidator;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.api.AuthFrontend;
import uk.gov.di.orchestration.shared.entity.Channel;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.ErrorResponse;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.exceptions.ClientNotFoundException;
import uk.gov.di.orchestration.shared.exceptions.ClientRedirectUriValidationException;
import uk.gov.di.orchestration.shared.exceptions.ClientSignatureValidationException;
import uk.gov.di.orchestration.shared.exceptions.JwksException;
import uk.gov.di.orchestration.shared.helpers.DocAppSubjectIdHelper;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.ClientService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.CrossBrowserOrchestrationService;
import uk.gov.di.orchestration.shared.services.DocAppAuthorisationService;
import uk.gov.di.orchestration.shared.services.OrchClientSessionService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
import uk.gov.di.orchestration.shared.services.TokenValidationService;
import uk.gov.di.orchestration.sharedtest.helper.TokenGeneratorHelper;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;
import uk.gov.di.orchestration.sharedtest.utils.KeyPairUtils;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static com.nimbusds.oauth2.sdk.OAuth2Error.INVALID_REQUEST;
import static java.lang.String.format;
import static java.time.Clock.fixed;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.oidc.domain.OidcAuditableEvent.AUTHORISATION_REQUEST_ERROR;
import static uk.gov.di.authentication.oidc.helper.RequestObjectTestHelper.generateSignedJWT;
import static uk.gov.di.authentication.oidc.helper.TestIdGeneratorHelper.runWithIds;
import static uk.gov.di.orchestration.shared.helpers.CookieHelper.SESSION_COOKIE_NAME;
import static uk.gov.di.orchestration.shared.helpers.CookieHelper.getHttpCookieFromMultiValueResponseHeaders;
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
    private final DocAppAuthorisationService docAppAuthorisationService =
            mock(DocAppAuthorisationService.class);
    private final OrchClientSessionService orchClientSessionService =
            mock(OrchClientSessionService.class);
    private final OrchClientSessionItem orchClientSession = mock(OrchClientSessionItem.class);
    private final OrchestrationAuthorizationService orchestrationAuthorizationService =
            mock(OrchestrationAuthorizationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final AuthFrontend authFrontend = mock(AuthFrontend.class);
    private final AuthorisationService authorisationService = mock(AuthorisationService.class);
    private final OrchSessionService orchSessionService = mock(OrchSessionService.class);

    private final CrossBrowserOrchestrationService crossBrowserOrchestrationService =
            mock(CrossBrowserOrchestrationService.class);
    private final TokenValidationService tokenValidationService =
            mock(TokenValidationService.class);
    private final RequestObjectAuthorizeValidator requestObjectAuthorizeValidator =
            mock(RequestObjectAuthorizeValidator.class);
    private final QueryParamsAuthorizeValidator queryParamsAuthorizeValidator =
            mock(QueryParamsAuthorizeValidator.class);
    private final RateLimitService rateLimitService = mock(RateLimitService.class);
    private final ClientService clientService = mock(ClientService.class);
    private static final String EXPECTED_NEW_SESSION_COOKIE_STRING =
            "gs=a-new-session-id.client-session-id; Max-Age=3600; Domain=auth.ida.digital.cabinet-office.gov.uk; Secure; HttpOnly;";
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
    private static final String NEW_SESSION_ID_FOR_PREV_SESSION = "a-prev-session-id";
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
    private static final KeyPair RSA_KEY_PAIR = KeyPairUtils.generateRsaKeyPair();
    private static final ECKey EC_SIGNING_KEY = generateECSigningKey();
    private static final String FIXED_TIMESTAMP = "2021-09-01T22:10:00.012Z";
    private static final Clock fixedClock = fixed(Instant.parse(FIXED_TIMESTAMP), ZoneId.of("UTC"));
    private static final NowHelper.NowClock fixedNowClock = new NowHelper.NowClock(fixedClock);

    static {
        try {
            TEST_ENCRYPTED_JWT = createEncryptedJWT();
        } catch (JOSEException | ParseException e) {
            throw new RuntimeException(e);
        }
    }

    private OrchSessionItem orchSession;
    private static final String NEW_CLIENT_SESSION_ID = "client-session-id";
    private static final State STATE = new State("rp-state");
    private static final Nonce NONCE = new Nonce();
    private static final Subject SUBJECT = new Subject();
    private static final String SERIALIZED_SIGNED_ID_TOKEN =
            TokenGeneratorHelper.generateIDToken(
                            CLIENT_ID.getValue(),
                            SUBJECT,
                            "http://localhost-rp",
                            NEW_CLIENT_SESSION_ID,
                            EC_SIGNING_KEY)
                    .serialize();
    private static final String ID_TOKEN_AUDIENCE = getIdTokenAudience();
    private static final String TXMA_ENCODED_HEADER_VALUE = "dGVzdAo=";
    private static final TxmaAuditUser BASE_AUDIT_USER =
            TxmaAuditUser.user()
                    .withGovukSigninJourneyId(NEW_CLIENT_SESSION_ID)
                    .withIpAddress("123.123.123.123")
                    .withPersistentSessionId(EXPECTED_PERSISTENT_COOKIE_VALUE_WITH_TIMESTAMP);
    private static final String SESSION_COOKIE =
            format("%s=%s.%s", SESSION_COOKIE_NAME, SESSION_ID, CLIENT_ID.getValue());

    private AuthorisationHandler handler;
    private ClientRegistry clientRegistry;

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(AuthorisationHandler.class);

    private final long timeNow = fixedNowClock.now().toInstant().getEpochSecond();

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
        when(context.getAwsRequestId()).thenReturn(AWS_REQUEST_ID);
        handler =
                new AuthorisationHandler(
                        configService,
                        orchSessionService,
                        orchClientSessionService,
                        orchestrationAuthorizationService,
                        auditService,
                        queryParamsAuthorizeValidator,
                        requestObjectAuthorizeValidator,
                        clientService,
                        docAppAuthorisationService,
                        cloudwatchMetricsService,
                        crossBrowserOrchestrationService,
                        tokenValidationService,
                        authFrontend,
                        authorisationService,
                        rateLimitService,
                        fixed(Instant.parse(FIXED_TIMESTAMP), ZoneId.of("UTC")));
        orchSession = new OrchSessionItem(SESSION_ID);
        when(orchClientSessionService.generateClientSession(any(), any(), any(), any(), any()))
                .thenReturn(orchClientSession);
        when(clientService.getClient(anyString()))
                .thenReturn(Optional.of(generateClientRegistry()));
        when(orchClientSession.getDocAppSubjectId()).thenReturn("test-subject-id");
        when(rateLimitService.getClientRateLimitDecision(any(ClientRateLimitConfig.class)))
                .thenReturn(RateLimitDecision.UNDER_LIMIT_NO_ACTION);
        clientRegistry = generateClientRegistry().withRateLimit(400);
        when(clientService.getClient(anyString())).thenReturn(Optional.of(clientRegistry));
    }

    @Nested
    class AuthJourney {

        @Test
        void shouldRedirectToLoginWhenUserHasNoExistingSession() {
            Map<String, String> requestParams = buildRequestParams(null);
            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);
            APIGatewayProxyResponseEvent response = makeHandlerRequest(event);
            URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

            assertThat(response, hasStatus(302));
            assertThat(uri.getQuery(), not(containsString("cookie_consent")));
            assertEquals(FRONT_END_BASE_URI.getAuthority(), uri.getAuthority());
            assertTrue(
                    response.getMultiValueHeaders()
                            .get(ResponseHeaders.SET_COOKIE)
                            .contains(EXPECTED_NEW_SESSION_COOKIE_STRING));
            var diPersistentCookieString =
                    response.getMultiValueHeaders().get(ResponseHeaders.SET_COOKIE).get(1);
            var sessionId =
                    extractSessionId(
                            diPersistentCookieString, EXPECTED_BASE_PERSISTENT_COOKIE_VALUE);
            assertTrue(isValidPersistentSessionCookieWithDoubleDashedTimestamp(sessionId));

            verify(orchSessionService).addSession(any());
            verify(orchClientSessionService).storeClientSession(orchClientSession);

            verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER.withSessionId(NEW_SESSION_ID),
                            pair("client-name", RP_CLIENT_NAME),
                            pair("new_authentication_required", false));
            verify(cloudwatchMetricsService)
                    .putEmbeddedValue(
                            "AuthRedirectQueryParamSize",
                            48,
                            Map.of("clientId", CLIENT_ID.getValue()));
        }

        @Test
        void shouldRedirectToLoginWhenUserHasNoExistingSessionWithSignedAndEncryptedJwtInBody()
                throws com.nimbusds.oauth2.sdk.ParseException, ParseException {
            var orchClientId = "orchestration-client-id";
            when(configService.getOrchestrationClientId()).thenReturn(orchClientId);
            when(orchestrationAuthorizationService.getSignedAndEncryptedJWT(any()))
                    .thenReturn(TEST_ENCRYPTED_JWT);

            var requestParams = buildRequestParams(null);
            var event = withRequestEvent(requestParams);
            var response = makeHandlerRequest(event);

            assertThat(response, hasStatus(302));
            var locationHeader = response.getHeaders().get(ResponseHeaders.LOCATION);
            verify(orchestrationAuthorizationService)
                    .storeState(eq(NEW_SESSION_ID), eq(NEW_CLIENT_SESSION_ID), any(State.class));
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
                            "{\"userinfo\":{\"local_account_id\":null, \"email_verified\":null,\"verified_mfa_method_type\":null,\"email\":null, \"uplift_required\":null, \"achieved_credential_strength\":null}}");
            var actualClaimSetRequest =
                    ClaimsSetRequest.parse(captor.getValue().getStringClaim("claim"));
            assertEquals(
                    expectedClaimSetRequest.toJSONObject(), actualClaimSetRequest.toJSONObject());
            verify(cloudwatchMetricsService)
                    .putEmbeddedValue(
                            "AuthRedirectQueryParamSize",
                            1003,
                            Map.of("clientId", CLIENT_ID.getValue()));
        }

        @Test
        void shouldPassTheCorrectClaimsToAuthForLowLevelTrustJourneys()
                throws com.nimbusds.oauth2.sdk.ParseException, ParseException {
            var orchClientId = "orchestration-client-id";
            when(configService.getOrchestrationClientId()).thenReturn(orchClientId);
            when(orchestrationAuthorizationService.getSignedAndEncryptedJWT(any()))
                    .thenReturn(TEST_ENCRYPTED_JWT);

            var requestParams =
                    buildRequestParams(Map.of("scope", "openid phone", "vtr", "[\"Cl\"]"));
            var event = withRequestEvent(requestParams);
            var response = makeHandlerRequest(event);

            assertThat(response, hasStatus(302));
            var locationHeader = response.getHeaders().get(ResponseHeaders.LOCATION);
            verify(orchestrationAuthorizationService)
                    .storeState(eq(NEW_SESSION_ID), eq(NEW_CLIENT_SESSION_ID), any(State.class));
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
                            "{\"userinfo\":{\"local_account_id\":null, \"phone_number_verified\":null,\"phone_number\":null,\"email\":null,\"verified_mfa_method_type\":null, \"uplift_required\":null, \"achieved_credential_strength\":null}}");
            var actualClaimSetRequest =
                    ClaimsSetRequest.parse(captor.getValue().getStringClaim("claim"));
            assertEquals(
                    expectedClaimSetRequest.toJSONObject(), actualClaimSetRequest.toJSONObject());
        }

        @Test
        void shouldPassTheCorrectClaimsToAuthForHighLevelTrustJourneys()
                throws com.nimbusds.oauth2.sdk.ParseException, ParseException {
            var orchClientId = "orchestration-client-id";
            when(configService.getOrchestrationClientId()).thenReturn(orchClientId);
            when(orchestrationAuthorizationService.getSignedAndEncryptedJWT(any()))
                    .thenReturn(TEST_ENCRYPTED_JWT);

            var requestParams =
                    buildRequestParams(Map.of("scope", "openid", "vtr", "[\"Cl.Cm.P2\"]"));
            var event = withRequestEvent(requestParams);

            var response = makeHandlerRequest(event);

            assertThat(response, hasStatus(302));
            var locationHeader = response.getHeaders().get(ResponseHeaders.LOCATION);
            verify(orchestrationAuthorizationService)
                    .storeState(eq(NEW_SESSION_ID), eq(NEW_CLIENT_SESSION_ID), any(State.class));
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
                            "{\"userinfo\":{\"salt\":null,\"email_verified\":null,\"local_account_id\":null,\"phone_number\":null,\"email\":null,\"verified_mfa_method_type\":null, \"uplift_required\":null , \"achieved_credential_strength\":null}}");
            var actualClaimSetRequest =
                    ClaimsSetRequest.parse(captor.getValue().getStringClaim("claim"));
            assertEquals(
                    expectedClaimSetRequest.toJSONObject(), actualClaimSetRequest.toJSONObject());
        }

        private static Stream<Arguments> clientChannelsAndExpectedChannels() {
            return Stream.of(
                    arguments(null, null, Channel.WEB.getValue()),
                    arguments(null, Channel.WEB.getValue(), Channel.WEB.getValue()),
                    arguments(
                            null,
                            Channel.STRATEGIC_APP.getValue(),
                            Channel.STRATEGIC_APP.getValue()),
                    arguments(null, Channel.GENERIC_APP.getValue(), Channel.GENERIC_APP.getValue()),
                    arguments(Channel.WEB.getValue(), null, Channel.WEB.getValue()),
                    arguments(Channel.GENERIC_APP.getValue(), null, Channel.GENERIC_APP.getValue()),
                    arguments(
                            Channel.GENERIC_APP.getValue(),
                            Channel.WEB.getValue(),
                            Channel.GENERIC_APP.getValue()));
        }

        @ParameterizedTest
        @MethodSource("clientChannelsAndExpectedChannels")
        void shouldPassTheCorrectChannelClaimToAuth(
                String authRequestChannel, String clientChannel, String expectedChannelClaim) {
            when(clientService.getClient(anyString()))
                    .thenReturn(Optional.of(generateClientRegistry().withChannel(clientChannel)));
            var requestParams = buildRequestParams(Map.of("scope", "openid profile phone"));
            if (authRequestChannel != null) {
                requestParams.put("channel", authRequestChannel);
            }
            var event = withRequestEvent(requestParams);

            makeHandlerRequest(event);

            var captor = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(captor.capture());
            var actualChannelClaim = captor.getValue().getClaim("channel");
            assertEquals(expectedChannelClaim, actualChannelClaim);
        }

        @ParameterizedTest
        @ValueSource(booleans = {true, false})
        void shouldPassAuthenticatedClaimToAuthFromOrchSession(boolean isAuthenticated) {
            withExistingSession();
            withExistingOrchSession(
                    new OrchSessionItem(NEW_SESSION_ID).withAuthenticated(isAuthenticated));

            var requestParams =
                    buildRequestParams(
                            Map.of("scope", "openid profile phone", "vtr", "[\"Cl.Cm.P2\"]"));
            var event = withRequestEvent(requestParams);

            makeHandlerRequest(event);

            var captor = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(captor.capture());
            var actualAuthenticatedClaim = captor.getValue().getClaim("authenticated");
            assertEquals(isAuthenticated, actualAuthenticatedClaim);
        }

        @Test
        void authenticatedClaimIsFalseIfNewSession() {
            withNoSession();

            var requestParams =
                    buildRequestParams(
                            Map.of("scope", "openid profile phone", "vtr", "[\"Cl.Cm.P2\"]"));
            var event = withRequestEvent(requestParams);

            makeHandlerRequest(event);

            var captor = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(captor.capture());
            var actualAuthenticatedClaim = captor.getValue().getClaim("authenticated");
            assertEquals(false, actualAuthenticatedClaim);
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

            APIGatewayProxyResponseEvent response = makeHandlerRequest(event);
            URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

            assertThat(response, hasStatus(302));
            assertThat(uri.getQuery(), not(containsString("cookie_consent")));
            assertEquals(FRONT_END_BASE_URI.getAuthority(), uri.getAuthority());
            assertTrue(
                    response.getMultiValueHeaders()
                            .get(ResponseHeaders.SET_COOKIE)
                            .contains(EXPECTED_NEW_SESSION_COOKIE_STRING));
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

            verify(orchClientSessionService).storeClientSession(orchClientSession);

            verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER.withSessionId(NEW_SESSION_ID),
                            pair("client-name", RP_CLIENT_NAME),
                            pair("new_authentication_required", false));
            verify(cloudwatchMetricsService)
                    .putEmbeddedValue(
                            "AuthRedirectQueryParamSize",
                            48,
                            Map.of("clientId", CLIENT_ID.getValue()));
        }

        @Test
        void shouldResetProcessingIdentityAttemptsWhenUpdatingAnExistingSession() {
            withExistingSession();
            var previousOrchSession = new OrchSessionItem(NEW_SESSION_ID).withAuthenticated(true);
            previousOrchSession.incrementProcessingIdentityAttempts();
            withExistingOrchSession(previousOrchSession);

            var requestParams =
                    buildRequestParams(
                            Map.of("scope", "openid profile phone", "vtr", "[\"Cl.Cm.P2\"]"));
            var event = withRequestEvent(requestParams);

            makeHandlerRequest(event);

            verify(orchSessionService, atLeastOnce())
                    .addSession(
                            argThat(
                                    orchSession ->
                                            orchSession.getAuthenticated()
                                                    && orchSession.getProcessingIdentityAttempts()
                                                            == 0));
            verify(orchSessionService, atLeastOnce()).deleteSession(NEW_SESSION_ID);
        }

        @Test
        void shouldRedirectToLoginWithPromptParamWhenSetToLoginAndExistingSessionIsPresent() {
            withExistingSession();
            var authRequestParams = generateAuthRequest(Optional.empty()).toParameters();
            when(orchClientSession.getAuthRequestParams()).thenReturn(authRequestParams);

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
                            .contains(EXPECTED_NEW_SESSION_COOKIE_STRING));
            var diPersistentCookieString =
                    response.getMultiValueHeaders().get(ResponseHeaders.SET_COOKIE).get(1);
            var sessionId =
                    extractSessionId(
                            diPersistentCookieString, EXPECTED_BASE_PERSISTENT_COOKIE_VALUE);
            assertTrue(isValidPersistentSessionCookieWithDoubleDashedTimestamp(sessionId));

            verify(orchSessionService).addSession(any());
            verify(orchSessionService).deleteSession(SESSION_ID);
            verify(orchClientSessionService).storeClientSession(orchClientSession);

            verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER.withSessionId(NEW_SESSION_ID),
                            pair("client-name", RP_CLIENT_NAME),
                            pair("new_authentication_required", false));
            verify(cloudwatchMetricsService)
                    .putEmbeddedValue(
                            "AuthRedirectQueryParamSize",
                            61,
                            Map.of("clientId", CLIENT_ID.getValue()));
        }

        @ParameterizedTest
        @ValueSource(booleans = {true, false})
        void shouldRetainGoogleAnalyticsParamThroughRedirectToLoginWhenClientIsFaceToFaceRp(
                boolean isAuthOrchSplitEnabled) {
            withExistingSession();
            var authRequestParams = generateAuthRequest(Optional.empty()).toParameters();
            when(orchClientSession.getAuthRequestParams()).thenReturn(authRequestParams);

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
        void shouldRedirectToLoginWhenSingleFactorInVtr() {
            withExistingSession();
            var authRequestParams =
                    generateAuthRequest(Optional.of(jsonArrayOf("Cl"))).toParameters();
            when(orchClientSession.getAuthRequestParams()).thenReturn(authRequestParams);

            APIGatewayProxyResponseEvent response =
                    makeHandlerRequest(
                            withRequestEvent(buildRequestParams(Map.of("vtr", "[\"Cl\"]"))));
            URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

            assertThat(response, hasStatus(302));
            assertEquals(FRONT_END_BASE_URI.getAuthority(), uri.getAuthority());

            assertTrue(
                    response.getMultiValueHeaders()
                            .get(ResponseHeaders.SET_COOKIE)
                            .contains(EXPECTED_NEW_SESSION_COOKIE_STRING));

            var diPersistentCookieString =
                    response.getMultiValueHeaders().get(ResponseHeaders.SET_COOKIE).get(1);
            var sessionId =
                    extractSessionId(
                            diPersistentCookieString, EXPECTED_BASE_PERSISTENT_COOKIE_VALUE);
            assertTrue(isValidPersistentSessionCookieWithDoubleDashedTimestamp(sessionId));

            verify(orchSessionService).addSession(any());
            verify(orchSessionService).deleteSession(SESSION_ID);
            verify(orchClientSessionService).storeClientSession(orchClientSession);

            verifyAuthorisationRequestParsedAuditEvent(
                    Map.of("credential_trust_level", "LOW_LEVEL"));

            verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER.withSessionId(NEW_SESSION_ID),
                            pair("client-name", RP_CLIENT_NAME),
                            pair("new_authentication_required", false));
            verify(cloudwatchMetricsService)
                    .putEmbeddedValue(
                            "AuthRedirectQueryParamSize",
                            48,
                            Map.of("clientId", CLIENT_ID.getValue()));
        }

        @Test
        void shouldRedirectToLoginWhenIdentityIsPresentInVtr() {
            withExistingSession();
            var authRequestParams =
                    generateAuthRequest(Optional.of(jsonArrayOf("P2.Cl.Cm"))).toParameters();
            when(orchClientSession.getAuthRequestParams()).thenReturn(authRequestParams);

            APIGatewayProxyResponseEvent response =
                    makeHandlerRequest(
                            withRequestEvent(buildRequestParams(Map.of("vtr", "[\"P2.Cl.Cm\"]"))));
            URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

            assertThat(response, hasStatus(302));
            assertEquals(FRONT_END_BASE_URI.getAuthority(), uri.getAuthority());

            assertTrue(
                    response.getMultiValueHeaders()
                            .get(ResponseHeaders.SET_COOKIE)
                            .contains(EXPECTED_NEW_SESSION_COOKIE_STRING));

            var diPersistentCookieString =
                    response.getMultiValueHeaders().get(ResponseHeaders.SET_COOKIE).get(1);
            var sessionId =
                    extractSessionId(
                            diPersistentCookieString, EXPECTED_BASE_PERSISTENT_COOKIE_VALUE);
            assertTrue(isValidPersistentSessionCookieWithDoubleDashedTimestamp(sessionId));

            verify(orchSessionService).addSession(any());
            verify(orchSessionService).deleteSession(SESSION_ID);
            verify(orchClientSessionService).storeClientSession(orchClientSession);

            verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER.withSessionId(NEW_SESSION_ID),
                            pair("client-name", RP_CLIENT_NAME),
                            pair("new_authentication_required", false));
            verify(cloudwatchMetricsService)
                    .putEmbeddedValue(
                            "AuthRedirectQueryParamSize",
                            48,
                            Map.of("clientId", CLIENT_ID.getValue()));
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

            APIGatewayProxyRequestEvent event =
                    withRequestEvent(
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

            makeHandlerRequest(event);

            ArgumentCaptor<com.nimbusds.oauth2.sdk.ParseException> parseExceptionArgument =
                    ArgumentCaptor.forClass(com.nimbusds.oauth2.sdk.ParseException.class);

            verify(authorisationService).classifyParseException(parseExceptionArgument.capture());
            assertEquals(
                    "Missing response_type parameter",
                    parseExceptionArgument.getValue().getMessage());
        }

        @ParameterizedTest
        @ValueSource(strings = {"POST", "PUT", "DELETE", "PATCH"})
        void shouldThrowExceptionWhenMethodIsNotGet(String method) {
            APIGatewayProxyRequestEvent event =
                    withRequestEvent(
                            Map.of(
                                    "client_id", "test-id",
                                    "redirect_uri", "http://localhost:8080",
                                    "scope", "email openid profile",
                                    "response_type", "code"));

            event.setHttpMethod(method);

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

            var jwtClaimsSet = buildjwtClaimsSet("https://localhost/authorize", null, null);
            var event =
                    withRequestEvent(
                            Map.of(
                                    "client_id",
                                    CLIENT_ID.getValue(),
                                    "scope",
                                    "openid",
                                    "response_type",
                                    "code",
                                    "request",
                                    generateSignedJWT(jwtClaimsSet, RSA_KEY_PAIR).serialize()));

            makeHandlerRequest(event);
            verify(requestObjectAuthorizeValidator).validate(any());
        }

        @Test
        void shouldValidateRequestObjectWhenJARValidationIsNotRequired()
                throws JOSEException, JwksException, ClientSignatureValidationException {
            when(orchestrationAuthorizationService.isJarValidationRequired(any()))
                    .thenReturn(false);

            var jwtClaimsSet = buildjwtClaimsSet("https://localhost/authorize", null, null);
            var event =
                    withRequestEvent(
                            Map.of(
                                    "client_id",
                                    CLIENT_ID.getValue(),
                                    "scope",
                                    "openid",
                                    "response_type",
                                    "code",
                                    "request",
                                    generateSignedJWT(jwtClaimsSet, RSA_KEY_PAIR).serialize()));

            makeHandlerRequest(event);
            verify(requestObjectAuthorizeValidator).validate(any());
        }

        @Test
        void shouldRedirectToLoginWhenRequestObjectIsValid()
                throws JOSEException, JwksException, ClientSignatureValidationException {
            when(requestObjectAuthorizeValidator.validate(any(AuthenticationRequest.class)))
                    .thenReturn(Optional.empty());

            var jwtClaimsSet = buildjwtClaimsSet("https://localhost/authorize", null, null);
            var event =
                    withRequestEvent(
                            Map.of(
                                    "client_id",
                                    CLIENT_ID.getValue(),
                                    "scope",
                                    "openid",
                                    "response_type",
                                    "code",
                                    "request",
                                    generateSignedJWT(jwtClaimsSet, RSA_KEY_PAIR).serialize()));

            var response = makeHandlerRequest(event);

            assertThat(response, hasStatus(302));
            var uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

            assertEquals(FRONT_END_BASE_URI.getAuthority(), uri.getAuthority());
            assertTrue(
                    response.getMultiValueHeaders()
                            .get(ResponseHeaders.SET_COOKIE)
                            .contains(EXPECTED_NEW_SESSION_COOKIE_STRING));
            var diPersistentCookieString =
                    response.getMultiValueHeaders().get(ResponseHeaders.SET_COOKIE).get(1);
            var sessionId =
                    extractSessionId(
                            diPersistentCookieString, EXPECTED_BASE_PERSISTENT_COOKIE_VALUE);
            assertTrue(isValidPersistentSessionCookieWithDoubleDashedTimestamp(sessionId));

            verify(orchSessionService).addSession(any());

            verify(requestObjectAuthorizeValidator).validate(any());

            verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER.withSessionId(NEW_SESSION_ID),
                            pair("client-name", RP_CLIENT_NAME),
                            pair("new_authentication_required", false));
            verify(cloudwatchMetricsService)
                    .putEmbeddedValue(
                            "AuthRedirectQueryParamSize",
                            48,
                            Map.of("clientId", CLIENT_ID.getValue()));
        }

        @Test
        void shouldReturnValidationFailedWhenSignatureIsInvalid()
                throws JOSEException, JwksException, ClientSignatureValidationException {
            when(requestObjectAuthorizeValidator.validate(any()))
                    .thenThrow(ClientSignatureValidationException.class);

            var jwtClaimsSet = buildjwtClaimsSet("https://localhost/authorize", null, null);
            var event =
                    withRequestEvent(
                            Map.of(
                                    "client_id",
                                    CLIENT_ID.getValue(),
                                    "scope",
                                    "openid",
                                    "response_type",
                                    "code",
                                    "request",
                                    generateSignedJWT(jwtClaimsSet, RSA_KEY_PAIR).serialize()));

            var response = makeHandlerRequest(event);
            assertEquals(400, response.getStatusCode());
            assertEquals("Trust chain validation failed", response.getBody());
        }

        @Test
        void shouldRedirectToLoginWhenMissingNonce()
                throws JOSEException, JwksException, ClientSignatureValidationException {
            when(requestObjectAuthorizeValidator.validate(any(AuthenticationRequest.class)))
                    .thenReturn(Optional.empty());
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

            var event =
                    withRequestEvent(
                            Map.of(
                                    "client_id",
                                    CLIENT_ID.getValue(),
                                    "scope",
                                    "openid",
                                    "response_type",
                                    "code",
                                    "request",
                                    generateSignedJWT(jwtClaimsSet, RSA_KEY_PAIR).serialize()));

            var response = makeHandlerRequest(event);

            assertThat(response, hasStatus(302));
            var uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

            assertEquals(FRONT_END_BASE_URI.getAuthority(), uri.getAuthority());
            assertTrue(
                    response.getMultiValueHeaders()
                            .get(ResponseHeaders.SET_COOKIE)
                            .contains(EXPECTED_NEW_SESSION_COOKIE_STRING));
            var diPersistentCookieString =
                    response.getMultiValueHeaders().get(ResponseHeaders.SET_COOKIE).get(1);
            var sessionId =
                    extractSessionId(
                            diPersistentCookieString, EXPECTED_BASE_PERSISTENT_COOKIE_VALUE);
            assertTrue(isValidPersistentSessionCookieWithDoubleDashedTimestamp(sessionId));
            verify(orchSessionService).addSession(any());

            verify(requestObjectAuthorizeValidator).validate(any());

            verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER.withSessionId(NEW_SESSION_ID),
                            pair("client-name", RP_CLIENT_NAME),
                            pair("new_authentication_required", false));
            verify(cloudwatchMetricsService)
                    .putEmbeddedValue(
                            "AuthRedirectQueryParamSize",
                            48,
                            Map.of("clientId", CLIENT_ID.getValue()));
        }

        @Test
        void shouldReturnServerErrorOnJwksException()
                throws JOSEException, JwksException, ClientSignatureValidationException {
            when(requestObjectAuthorizeValidator.validate(any())).thenThrow(JwksException.class);

            var jwtClaimsSet = buildjwtClaimsSet("https://localhost/authorize", null, null);

            var event =
                    withRequestEvent(
                            Map.of(
                                    "client_id",
                                    CLIENT_ID.getValue(),
                                    "scope",
                                    "openid",
                                    "response_type",
                                    "code",
                                    "request",
                                    generateSignedJWT(jwtClaimsSet, RSA_KEY_PAIR).serialize()));

            var response = makeHandlerRequest(event);
            assertEquals(500, response.getStatusCode());
            assertEquals("Unexpected server error", response.getBody());
        }

        @Test
        void shouldSendAuditRequestParsedWithRpSidPresent() {
            var rpSid = "test-rp-sid";
            Map<String, String> requestParams = buildRequestParams(Map.of("rp_sid", rpSid));
            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);

            makeHandlerRequest(event);
            verifyAuthorisationRequestParsedAuditEvent(Map.of("rpSid", rpSid));
        }

        @Test
        void shouldSendAuditRequestParsedWhenRpSidNotPresent() {
            Map<String, String> requestParams = buildRequestParams(null);
            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);

            makeHandlerRequest(event);

            verifyAuthorisationRequestParsedAuditEvent();
        }

        @Test
        void shouldSendAuditRequestParsedWhenOnAuthOnlyFlow() {
            Map<String, String> requestParams = buildRequestParams(Map.of("vtr", "[\"Cl.Cm\"]"));
            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);

            makeHandlerRequest(event);

            verifyAuthorisationRequestParsedAuditEvent();
        }

        @Test
        void shouldSendAuditRequestParsedWhenOnIdentityFlow() {
            Map<String, String> requestParams = buildRequestParams(Map.of("vtr", "[\"P2.Cl.Cm\"]"));
            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);

            makeHandlerRequest(event);

            verifyAuthorisationRequestParsedAuditEvent(Map.of("identityRequested", true));
        }

        @Test
        void shouldSendAuditRequestParsedWithMaxAgeExtensionWhenSupportedByClient() {
            var client = generateClientRegistry();
            client.setMaxAgeEnabled(true);
            when(clientService.getClient(anyString())).thenReturn(Optional.of(client));
            Map<String, String> requestParams =
                    buildRequestParams(Map.of("vtr", "[\"Cl.Cm\"]", "max_age", "123"));
            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);

            makeHandlerRequest(event);
            verifyAuthorisationRequestParsedAuditEvent(Map.of("maximumSessionAge", 123));
        }

        @Test
        void shouldSendAuditRequestParsedWithChannel() {
            var client = generateClientRegistry();
            client.setMaxAgeEnabled(true);
            when(clientService.getClient(anyString())).thenReturn(Optional.of(client));
            Map<String, String> requestParams =
                    buildRequestParams(Map.of("channel", Channel.GENERIC_APP.toString()));
            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);

            makeHandlerRequest(event);

            verifyAuthorisationRequestParsedAuditEvent(
                    Map.of("channel", Channel.GENERIC_APP.toString()));
        }

        @Test
        void shouldAddPreviousSessionIdClaimIfThereIsAnExistingOrchSession() throws ParseException {
            when(orchSessionService.getSession(SESSION_ID)).thenReturn(Optional.of(orchSession));

            var requestParams =
                    buildRequestParams(
                            Map.of("scope", "openid profile phone", "vtr", "[\"Cl.Cm.P2\"]"));

            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);

            makeHandlerRequest(event);

            ArgumentCaptor<JWTClaimsSet> argument = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(argument.capture());
            assertThat(
                    argument.getValue().getStringClaim("previous_session_id"), equalTo(SESSION_ID));
        }

        @Test
        void shouldNotAddPreviousSessionIdWhenSessionCookiePresentButNotOrchSession()
                throws ParseException {
            when(orchSessionService.getSession(SESSION_ID)).thenReturn(Optional.empty());

            var requestParams =
                    buildRequestParams(
                            Map.of("scope", "openid profile phone", "vtr", "[\"Cl.Cm.P2\"]"));

            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);

            makeHandlerRequest(event);

            ArgumentCaptor<JWTClaimsSet> argument = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(argument.capture());
            assertNull(argument.getValue().getStringClaim("previous_session_id"));
        }

        @Test
        void shouldAddPublicSubjectIdClaimIfAmScopePresent()
                throws com.nimbusds.oauth2.sdk.ParseException, ParseException {
            Map<String, String> requestParams = buildRequestParams(Map.of("scope", "openid am"));
            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);

            makeHandlerRequest(event);

            verifyAuthorisationRequestParsedAuditEvent();
            ArgumentCaptor<JWTClaimsSet> argument = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(argument.capture());

            var expectedClaim =
                    ClaimsSetRequest.parse(
                            "{\"userinfo\":{\"local_account_id\":null, \"verified_mfa_method_type\":null,\"public_subject_id\":null,\"email\":null, \"uplift_required\":null, \"achieved_credential_strength\":null}}");
            var actualClaim = ClaimsSetRequest.parse(argument.getValue().getStringClaim("claim"));
            assertEquals(actualClaim.toJSONObject(), expectedClaim.toJSONObject());
        }

        @Test
        void shouldAddPublicSubjectIdClaimIfClientHasPublicSubjectTypePresent()
                throws com.nimbusds.oauth2.sdk.ParseException, ParseException {
            when(clientService.getClient(CLIENT_ID.getValue()))
                    .thenReturn(Optional.of(generateClientRegistry().withSubjectType("public")));

            Map<String, String> requestParams = buildRequestParams(Map.of("scope", "openid"));
            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);

            makeHandlerRequest(event);

            verifyAuthorisationRequestParsedAuditEvent();
            ArgumentCaptor<JWTClaimsSet> argument = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(argument.capture());

            var expectedClaim =
                    ClaimsSetRequest.parse(
                            "{\"userinfo\":{\"local_account_id\":null, \"verified_mfa_method_type\":null,\"public_subject_id\":null,\"email\":null, \"uplift_required\":null, \"achieved_credential_strength\":null}}");
            var actualClaim = ClaimsSetRequest.parse(argument.getValue().getStringClaim("claim"));
            assertEquals(actualClaim.toJSONObject(), expectedClaim.toJSONObject());
        }

        @Test
        void shouldAddLegacySubjectIdClaimIfGovUkAccountScopePresent()
                throws com.nimbusds.oauth2.sdk.ParseException, ParseException {
            Map<String, String> requestParams =
                    buildRequestParams(Map.of("scope", "openid govuk-account"));
            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);

            makeHandlerRequest(event);

            verifyAuthorisationRequestParsedAuditEvent();
            ArgumentCaptor<JWTClaimsSet> argument = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(argument.capture());

            var expectedClaim =
                    ClaimsSetRequest.parse(
                            "{\"userinfo\":{\"legacy_subject_id\":null,\"local_account_id\":null,\"verified_mfa_method_type\":null,\"email\":null, \"uplift_required\":null, \"achieved_credential_strength\":null}}");
            var actualClaim = ClaimsSetRequest.parse(argument.getValue().getStringClaim("claim"));
            assertEquals(actualClaim.toJSONObject(), expectedClaim.toJSONObject());
        }

        @Test
        void shouldSetTheRelevantCookiesInTheHeader() {
            Map<String, String> requestParams = buildRequestParams(null);
            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);

            var response = makeHandlerRequest(event);

            assertTrue(
                    response.getMultiValueHeaders()
                            .get(ResponseHeaders.SET_COOKIE)
                            .get(0)
                            .contains(EXPECTED_NEW_SESSION_COOKIE_STRING));
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
                                            BROWSER_SESSION_ID_COOKIE_NAME,
                                            NEW_BROWSER_SESSION_ID)));
        }
    }

    @Nested
    class Reauthentication {
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

            makeHandlerRequest(event);

            verifyAuthorisationRequestParsedAuditEvent(Map.of("reauthRequested", true));

            ArgumentCaptor<JWTClaimsSet> argument = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(argument.capture());
            assertThat(
                    argument.getValue().getStringClaim("reauthenticate"),
                    equalTo(SUBJECT.getValue()));
            assertThat(
                    argument.getValue().getStringClaim("previous_govuk_signin_journey_id"),
                    equalTo(NEW_CLIENT_SESSION_ID));
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

            makeHandlerRequest(event);

            verifyAuthorisationRequestParsedAuditEvent();

            ArgumentCaptor<JWTClaimsSet> argument = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(argument.capture());
            assertNull(argument.getValue().getClaim("reauthenticate"));
            assertNull(argument.getValue().getClaim("previous_govuk_signin_journey_id"));
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

            verifyAuthorisationRequestParsedAuditEvent(Map.of("reauthRequested", true));

            verify(auditService)
                    .submitAuditEvent(
                            AUTHORISATION_REQUEST_ERROR,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER.withSessionId(NEW_SESSION_ID),
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

            verifyAuthorisationRequestParsedAuditEvent(Map.of("reauthRequested", true));

            verify(auditService)
                    .submitAuditEvent(
                            AUTHORISATION_REQUEST_ERROR,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER.withSessionId(NEW_SESSION_ID),
                            pair("description", expectedErrorObject.getDescription()));
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
            assertThat(
                    argument.getValue().getClaim("requested_credential_strength"),
                    equalTo("Cl.Cm"));
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

            makeHandlerRequest(event);

            verifyAuthorisationRequestParsedAuditEvent();

            ArgumentCaptor<JWTClaimsSet> argument = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(argument.capture());
            assertNull(argument.getValue().getClaim("reauthenticate"));
            assertNull(argument.getValue().getClaim("previous_govuk_signin_journey_id"));
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

            makeHandlerRequest(event);

            verifyAuthorisationRequestParsedAuditEvent();

            ArgumentCaptor<JWTClaimsSet> argument = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService).getSignedAndEncryptedJWT(argument.capture());
            assertNull(argument.getValue().getClaim("reauthenticate"));
            assertNull(argument.getValue().getClaim("previous_govuk_signin_journey_id"));
        }
    }

    @Test
    void shouldCreateANewSessionAndAttachTheClientSessionIdToIt() {
        var requestParams =
                buildRequestParams(
                        Map.of("scope", "openid profile phone", "vtr", "[\"Cl.Cm.P2\"]"));

        APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);
        makeHandlerRequest(event);
        verify(orchSessionService)
                .addSession(
                        argThat(
                                os ->
                                        os.getClientSessions().size() == 1
                                                && os.getClientSessions()
                                                        .contains(NEW_CLIENT_SESSION_ID)));
    }

    @Test
    void shouldAddANewClientSessionToAnExistingOrchSession() {
        withExistingOrchSession(orchSession.addClientSession("previous-client-session"));
        withExistingSession();
        var requestParams =
                buildRequestParams(
                        Map.of("scope", "openid profile phone", "vtr", "[\"Cl.Cm.P2\"]"));

        APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);
        makeHandlerRequest(event);

        verify(orchSessionService)
                .addSession(
                        argThat(
                                os ->
                                        os.getClientSessions().size() == 2
                                                && os.getClientSessions()
                                                        .contains(NEW_CLIENT_SESSION_ID)
                                                && os.getClientSessions()
                                                        .contains("previous-client-session")));
    }

    @Nested
    class BrowserSessionId {
        private final ArgumentCaptor<OrchSessionItem> orchSessionCaptor =
                ArgumentCaptor.forClass(OrchSessionItem.class);

        @Test
        void shouldCreateNewSessionWithNewBSIDWhenNeitherSessionNorBSIDCookiePresent() {
            withExistingOrchSession(null);
            APIGatewayProxyResponseEvent response = makeRequestWithBSIDInCookie(null);

            verify(orchSessionService).addSession(orchSessionCaptor.capture());
            var actualOrchSession = orchSessionCaptor.getValue();
            assertEquals(NEW_SESSION_ID, actualOrchSession.getSessionId());
            assertEquals(NEW_BROWSER_SESSION_ID, actualOrchSession.getBrowserSessionId());

            assertEquals(
                    format(
                            "%s=%s; Domain=oidc.auth.ida.digital.cabinet-office.gov.uk; Secure; HttpOnly;",
                            BROWSER_SESSION_ID_COOKIE_NAME, NEW_BROWSER_SESSION_ID),
                    browserSessionIdCookieFromResponse(response));
            verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER.withSessionId(NEW_SESSION_ID),
                            pair("client-name", RP_CLIENT_NAME),
                            pair("new_authentication_required", false));
        }

        @Test
        void shouldCreateNewSessionWithNewBSIDWhenNoSessionButCookieBSIDPresent() {
            withExistingOrchSession(null);
            APIGatewayProxyResponseEvent response = makeRequestWithBSIDInCookie(BROWSER_SESSION_ID);

            verify(orchSessionService).addSession(orchSessionCaptor.capture());
            var actualOrchSession = orchSessionCaptor.getValue();
            assertEquals(NEW_SESSION_ID, actualOrchSession.getSessionId());
            assertEquals(NEW_BROWSER_SESSION_ID, actualOrchSession.getBrowserSessionId());

            assertEquals(
                    format(
                            "%s=%s; Domain=oidc.auth.ida.digital.cabinet-office.gov.uk; Secure; HttpOnly;",
                            BROWSER_SESSION_ID_COOKIE_NAME, NEW_BROWSER_SESSION_ID),
                    browserSessionIdCookieFromResponse(response));
            verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER.withSessionId(NEW_SESSION_ID),
                            pair("client-name", RP_CLIENT_NAME),
                            pair("new_authentication_required", false));
        }

        @Test
        void shouldCreateNewSessionWhenSessionHasBSIDButCookieDoesNot() {
            withExistingOrchSession(orchSession.withBrowserSessionId(BROWSER_SESSION_ID));
            APIGatewayProxyResponseEvent response = makeRequestWithBSIDInCookie(null);

            verify(orchSessionService).addSession(orchSessionCaptor.capture());
            var actualOrchSession = orchSessionCaptor.getValue();
            assertEquals(NEW_SESSION_ID, actualOrchSession.getSessionId());
            assertEquals(NEW_BROWSER_SESSION_ID, actualOrchSession.getBrowserSessionId());

            assertEquals(
                    format(
                            "%s=%s; Domain=oidc.auth.ida.digital.cabinet-office.gov.uk; Secure; HttpOnly;",
                            BROWSER_SESSION_ID_COOKIE_NAME, NEW_BROWSER_SESSION_ID),
                    browserSessionIdCookieFromResponse(response));
            verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER.withSessionId(NEW_SESSION_ID),
                            pair("client-name", RP_CLIENT_NAME),
                            pair("new_authentication_required", true));
        }

        @Test
        void shouldUseExistingSessionWithNoBSIDEvenWhenBSIDCookiePresent() {
            withExistingOrchSession(orchSession.withBrowserSessionId(null));
            var response = makeRequestWithBSIDInCookie(BROWSER_SESSION_ID);

            verify(orchSessionService).addSession(orchSessionCaptor.capture());
            var actualOrchSession = orchSessionCaptor.getValue();
            assertEquals(NEW_SESSION_ID, actualOrchSession.getSessionId());
            assertNull(actualOrchSession.getBrowserSessionId());

            assertEquals(2, response.getMultiValueHeaders().get(ResponseHeaders.SET_COOKIE).size());
            assertTrue(
                    response.getMultiValueHeaders().get(ResponseHeaders.SET_COOKIE).stream()
                            .noneMatch(
                                    it ->
                                            it.startsWith(
                                                    format(
                                                            "%s=",
                                                            BROWSER_SESSION_ID_COOKIE_NAME))));
            verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER.withSessionId(NEW_SESSION_ID),
                            pair("client-name", RP_CLIENT_NAME),
                            pair("new_authentication_required", false));
        }

        @Test
        void shouldUseExistingSessionWhenSessionBSIDMatchesBSIDInCookie() {
            withExistingOrchSession(orchSession.withBrowserSessionId(BROWSER_SESSION_ID));
            APIGatewayProxyResponseEvent response = makeRequestWithBSIDInCookie(BROWSER_SESSION_ID);

            verify(orchSessionService).addSession(orchSessionCaptor.capture());
            var actualOrchSession = orchSessionCaptor.getValue();
            assertEquals(NEW_SESSION_ID, actualOrchSession.getSessionId());
            assertEquals(BROWSER_SESSION_ID, actualOrchSession.getBrowserSessionId());

            assertEquals(
                    format(
                            "%s=%s; Domain=oidc.auth.ida.digital.cabinet-office.gov.uk; Secure; HttpOnly;",
                            BROWSER_SESSION_ID_COOKIE_NAME, BROWSER_SESSION_ID),
                    browserSessionIdCookieFromResponse(response));
            verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER.withSessionId(NEW_SESSION_ID),
                            pair("client-name", RP_CLIENT_NAME),
                            pair("new_authentication_required", false));
        }

        @Test
        void shouldCreateNewSessionWhenSessionAndCookieBSIDDoNotMatch() {
            withExistingOrchSession(orchSession.withBrowserSessionId(BROWSER_SESSION_ID));
            APIGatewayProxyResponseEvent response =
                    makeRequestWithBSIDInCookie(DIFFERENT_BROWSER_SESSION_ID);

            verify(orchSessionService).addSession(orchSessionCaptor.capture());
            var actualOrchSession = orchSessionCaptor.getValue();
            assertEquals(NEW_SESSION_ID, actualOrchSession.getSessionId());
            assertEquals(NEW_BROWSER_SESSION_ID, actualOrchSession.getBrowserSessionId());

            assertEquals(
                    format(
                            "%s=%s; Domain=oidc.auth.ida.digital.cabinet-office.gov.uk; Secure; HttpOnly;",
                            BROWSER_SESSION_ID_COOKIE_NAME, NEW_BROWSER_SESSION_ID),
                    browserSessionIdCookieFromResponse(response));
            verify(auditService)
                    .submitAuditEvent(
                            OidcAuditableEvent.AUTHORISATION_INITIATED,
                            CLIENT_ID.getValue(),
                            BASE_AUDIT_USER.withSessionId(NEW_SESSION_ID),
                            pair("client-name", RP_CLIENT_NAME),
                            pair("new_authentication_required", true));
        }

        private APIGatewayProxyResponseEvent makeRequestWithBSIDInCookie(
                String browserSessionIdFromCookie) {
            Map<String, String> requestParams = buildRequestParams(null);
            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);

            var cookieString = SESSION_COOKIE;
            if (browserSessionIdFromCookie != null) {
                cookieString =
                        format(
                                "%s;%s=%s",
                                cookieString,
                                BROWSER_SESSION_ID_COOKIE_NAME,
                                browserSessionIdFromCookie);
            }
            event.withHeaders(Map.of("Cookie", cookieString));
            return makeHandlerRequest(event);
        }
    }

    @Nested
    class DocAppJourney {
        MockedStatic<DocAppSubjectIdHelper> docAppSubjectIdHelperMock;
        EncryptedJWT encryptedJwt;

        @BeforeEach()
        void docAppSetup() throws ParseException, JOSEException {

            var docAppClientRegistry =
                    generateClientRegistry().withClientType(ClientType.APP.getValue());

            when(clientService.getClient(CLIENT_ID.getValue()))
                    .thenReturn(Optional.of(docAppClientRegistry));

            docAppSubjectIdHelperMock = mockStatic(DocAppSubjectIdHelper.class);

            var uri = URI.create("someUri");
            when(configService.getDocAppDomain()).thenReturn(uri);
            when(DocAppSubjectIdHelper.calculateDocAppSubjectId(any(), anyBoolean(), any()))
                    .thenReturn(new Subject("calculatedSubjectId"));
            when(configService.getDocAppAuthorisationClientId()).thenReturn(CLIENT_ID.getValue());
            when(configService.getDocAppAuthorisationURI())
                    .thenReturn(URI.create(DOC_APP_REDIRECT_URI));
            encryptedJwt = createEncryptedJWT();
            when(docAppAuthorisationService.constructRequestJWT(any(), anyString(), any(), any()))
                    .thenReturn(encryptedJwt);
        }

        @AfterEach()
        void docAppTearDown() {
            docAppSubjectIdHelperMock.close();
        }

        @Test
        void shouldAddANewClientSessionToAnExistingOrchSession() throws JOSEException {
            withExistingOrchSession(orchSession.addClientSession("previous-client-session"));
            makeDocAppHandlerRequest();
            verify(orchSessionService)
                    .updateSession(
                            argThat(
                                    os ->
                                            os.getClientSessions().size() == 2
                                                    && os.getClientSessions()
                                                            .contains("previous-client-session")
                                                    && os.getClientSessions()
                                                            .contains(NEW_CLIENT_SESSION_ID)));
        }

        @Test
        void shouldAddANewClientSessionToANewOrchSession() throws JOSEException {
            makeDocAppHandlerRequest();
            verify(orchSessionService)
                    .addSession(
                            argThat(
                                    os ->
                                            os.getClientSessions().size() == 1
                                                    && os.getClientSessions()
                                                            .contains(NEW_CLIENT_SESSION_ID)));
        }

        @Test
        void shouldSaveStateAndStoreItToClientSession() throws JOSEException {
            makeDocAppHandlerRequest();
            verify(docAppAuthorisationService).storeState(eq(NEW_SESSION_ID), any());
            verify(crossBrowserOrchestrationService)
                    .storeClientSessionIdAgainstState(eq(NEW_CLIENT_SESSION_ID), any());
        }

        @Test
        void shouldUpdateOrchSessionWhenThereIsAnExistingSession() throws JOSEException {
            withExistingSession();
            when(orchSessionService.addOrUpdateSessionId(any(), any())).thenReturn(orchSession);

            makeDocAppHandlerRequest();

            verify(orchSessionService)
                    .addOrUpdateSessionId(Optional.of(orchSession.getSessionId()), NEW_SESSION_ID);
            verify(orchSessionService).updateSession(orchSession);
        }

        @Test
        void shouldSetTheRelevantCookiesInTheHeader() throws JOSEException {
            var response = makeDocAppHandlerRequest();

            verify(orchSessionService).addSession(any());
            assertTrue(
                    response.getMultiValueHeaders()
                            .get(ResponseHeaders.SET_COOKIE)
                            .contains(EXPECTED_NEW_SESSION_COOKIE_STRING));
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

            verify(orchSessionService).addSession(any());
            verify(orchClientSessionService).storeClientSession(any());

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
                                    .withSessionId(NEW_SESSION_ID)
                                    .withUserId("test-subject-id"));
        }
    }

    @Nested
    class InvalidRequestNonRedirecting {
        @Test
        void shouldReturn400WhenAuthorisationRequestContainsInvalidRedirectUri() {
            when(queryParamsAuthorizeValidator.validate(any(AuthenticationRequest.class)))
                    .thenThrow(ClientRedirectUriValidationException.class);

            APIGatewayProxyRequestEvent event =
                    withRequestEvent(
                            Map.of(
                                    "client_id", "test-id",
                                    "redirect_uri", "http://incorrect-redirect-uri",
                                    "scope", "email openid profile",
                                    "response_type", "code",
                                    "state", "test-state"));

            APIGatewayProxyResponseEvent response = makeHandlerRequest(event);

            assertThat(response, hasStatus(400));
            assertThat(response, hasBody("Invalid request"));
        }

        @Test
        void shouldReturn400WhenNoQueryStringParametersArePresent() {
            APIGatewayProxyRequestEvent event = withRequestEvent(null);

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

        @Test
        void shouldReturn400ForOpenRedirect()
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

        @Test
        void shouldReturn400WhenMissingClientId()
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
        void shouldReturn400WhenMissingRedirectUri()
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
        void shouldReturn400WhenIncorrectRedirectUri()
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
        void shouldReturn400WhenClientNotFound()
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
                                    format(
                                            "No Client found for ClientID: %s",
                                            CLIENT_ID.getValue())));
        }

        @Test
        void shouldReturn400WhenInvalidPromptValuesArePassed() {
            Map<String, String> requestParams =
                    buildRequestParams(Map.of("prompt", "select_account"));
            APIGatewayProxyResponseEvent response =
                    makeHandlerRequest(withRequestEvent(requestParams));
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
        void
                shouldReturn400WhenJARIsRequiredButRequestObjectIsMissingAndRedirectUriIsNotInClientRegistry() {
            when(orchestrationAuthorizationService.isJarValidationRequired(any())).thenReturn(true);
            var event =
                    withRequestEvent(
                            Map.of(
                                    "client_id",
                                    CLIENT_ID.getValue(),
                                    "scope",
                                    SCOPE,
                                    "redirect_uri",
                                    "invalid-redirect-uri",
                                    "response_type",
                                    "code"));

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
    }

    @Nested
    class InvalidRequestRedirectingErrors {
        @Test
        void shouldReturn302WithErrorQueryParamsWhenAuthorisationRequestContainsInvalidScope() {
            when(queryParamsAuthorizeValidator.validate(any(AuthenticationRequest.class)))
                    .thenReturn(
                            Optional.of(
                                    new AuthRequestError(
                                            OAuth2Error.INVALID_SCOPE,
                                            URI.create("http://localhost:8080"),
                                            new State("test-state"))));

            APIGatewayProxyRequestEvent event =
                    withRequestEvent(
                            Map.of(
                                    "client_id", "test-id",
                                    "redirect_uri", "http://localhost:8080",
                                    "scope", "email openid profile non-existent-scope",
                                    "response_type", "code",
                                    "state", "test-state"));

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
            var jwtClaimsSet = buildjwtClaimsSet("https://localhost/authorize", null, null);
            var event =
                    withRequestEvent(
                            Map.of(
                                    "client_id",
                                    CLIENT_ID.getValue(),
                                    "scope",
                                    "openid",
                                    "response_type",
                                    "code",
                                    "request",
                                    generateSignedJWT(jwtClaimsSet, RSA_KEY_PAIR).serialize()));

            var response = makeHandlerRequest(event);

            assertThat(response, hasStatus(302));
            assertEquals(
                    "http://localhost:8080?error=invalid_scope&error_description=Invalid%2C+unknown+or+malformed+scope&state=test-state",
                    response.getHeaders().get(ResponseHeaders.LOCATION));
        }

        @Test
        void shouldReturn302WithErrorQueryParamsWhenClientIsNotActive() {
            when(clientService.getClient(CLIENT_ID.toString()))
                    .thenReturn(Optional.of(generateClientRegistry().withActive(false)));

            var event =
                    withRequestEvent(
                            Map.of(
                                    "client_id",
                                    CLIENT_ID.getValue(),
                                    "scope",
                                    SCOPE,
                                    "redirect_uri",
                                    REDIRECT_URI,
                                    "response_type",
                                    "code"));

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
        void
                shouldRedirectToProvidedRedirectUriWhenJARIsRequiredButRequestObjectIsMissingAndRedirectUriIsInClientRegistry() {
            when(orchestrationAuthorizationService.isJarValidationRequired(any())).thenReturn(true);

            var event =
                    withRequestEvent(
                            Map.of(
                                    "client_id",
                                    CLIENT_ID.getValue(),
                                    "scope",
                                    SCOPE,
                                    "redirect_uri",
                                    REDIRECT_URI,
                                    "response_type",
                                    "code"));

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
        void shouldRedirectToRPWhenClientIsRateLimited() {
            when(rateLimitService.getClientRateLimitDecision(any(ClientRateLimitConfig.class)))
                    .thenReturn(RateLimitDecision.OVER_LIMIT_RETURN_TO_RP);

            Map<String, String> requestParams = buildRequestParams(null);
            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);
            var response = makeHandlerRequest(event);

            assertThat(response, hasStatus(302));
            assertEquals(
                    "https://localhost:8080?error=temporarily_unavailable&error_description=The+authorization+server+is+temporarily+unavailable&state="
                            + STATE.getValue(),
                    response.getHeaders().get(ResponseHeaders.LOCATION));
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
                                            errorObject,
                                            URI.create("http://localhost:8080"),
                                            null)));

            var event =
                    withRequestEvent(
                            Map.of(
                                    "client_id",
                                    "test-id",
                                    "scope",
                                    "openid",
                                    "response_type",
                                    "code",
                                    "request",
                                    new PlainJWT(new JWTClaimsSet.Builder().build()).serialize()));

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
    }

    @Nested
    class MaxAge {
        @BeforeEach
        void setup() {
            when(configService.getSessionExpiry()).thenReturn(3600L);
            orchSession.incrementProcessingIdentityAttempts();
            withExistingSession();
        }

        @Test
        void shouldNotUpdateSessionWhenThereIsNoExistingSession() {
            withNoSession();
            var requestParams =
                    buildRequestParams(
                            Map.of(
                                    "scope",
                                    "openid profile phone",
                                    "vtr",
                                    "[\"Cl.Cm.P2\"]",
                                    "max_age",
                                    "1000"));
            var event = withRequestEvent(requestParams);

            makeRequestWithSessionIdInCookie(event);

            ArgumentCaptor<OrchSessionItem> captor = ArgumentCaptor.forClass(OrchSessionItem.class);
            verify(orchSessionService).addSession(captor.capture());
            OrchSessionItem updatedSession = captor.getValue();

            assertFalse(updatedSession.getAuthenticated());
            assertNull(updatedSession.getPreviousSessionId());
            verify(orchSessionService, never()).deleteSession(anyString());
        }

        @Test
        void shouldNotUpdateSessionDueToMaxAgeWhenMaxAgeIsNotEnabledForClient() {
            when(clientService.getClient(anyString()))
                    .thenReturn(Optional.of(generateClientRegistry().withMaxAgeEnabled(false)));
            withExistingOrchSession(
                    orchSession.withAuthenticated(true).withPreviousSessionId("prev-session-id"));
            var requestParams =
                    buildRequestParams(
                            Map.of(
                                    "scope",
                                    "openid profile phone",
                                    "vtr",
                                    "[\"Cl.Cm.P2\"]",
                                    "max_age",
                                    "1000"));
            var event = withRequestEvent(requestParams);

            makeRequestWithSessionIdInCookie(event);

            ArgumentCaptor<OrchSessionItem> captor = ArgumentCaptor.forClass(OrchSessionItem.class);
            verify(orchSessionService).addSession(captor.capture());
            OrchSessionItem updatedSession = captor.getValue();

            assertTrue(updatedSession.getAuthenticated());
            assertThat(updatedSession.getPreviousSessionId(), equalTo("prev-session-id"));
            verify(orchSessionService).addSession(updatedSession);
            verify(orchSessionService).deleteSession(orchSession.getSessionId());
        }

        private static Stream<Arguments> authTimeAndMaxAgeParams() {
            var recentAuthTime = fixedNowClock.now().toInstant().getEpochSecond() - 1;
            return Stream.of(
                    arguments(recentAuthTime, "0", true),
                    arguments(12345L, "1800", true),
                    arguments(recentAuthTime - 1000, "800", true),
                    arguments(recentAuthTime - 1000, "1800", false),
                    arguments(recentAuthTime, "-1", false),
                    arguments(null, "1800", false),
                    arguments(99999999999L, "1800", false),
                    arguments(-123L, "1800", false));
        }

        @ParameterizedTest
        @MethodSource("authTimeAndMaxAgeParams")
        void shouldUpdateOrchSessionCorrectlyForQueryParametersRequest(
                Long authTime, String maxAgeParam, boolean maxAgeExpired) {
            when(clientService.getClient(anyString()))
                    .thenReturn(Optional.of(generateClientRegistry().withMaxAgeEnabled(true)));
            orchSession.incrementProcessingIdentityAttempts();
            withExistingOrchSession(orchSession.withAuthenticated(true).withAuthTime(authTime));
            var requestParams =
                    buildRequestParams(
                            Map.of(
                                    "scope",
                                    "openid profile phone",
                                    "vtr",
                                    "[\"Cl.Cm.P2\"]",
                                    "max_age",
                                    maxAgeParam));
            var event = withRequestEvent(requestParams);

            var response = makeRequestWithSessionIdInCookie(event);
            var sessionCookie =
                    getHttpCookieFromMultiValueResponseHeaders(
                            response.getMultiValueHeaders(), "gs");
            var newSessionId = sessionCookie.get().getValue().split("\\.")[0];

            ArgumentCaptor<OrchSessionItem> addSessionCaptor =
                    ArgumentCaptor.forClass(OrchSessionItem.class);
            if (maxAgeExpired) {
                verify(orchSessionService, times(2)).addSession(addSessionCaptor.capture());
                OrchSessionItem updatedPreviousSession = addSessionCaptor.getAllValues().get(0);
                OrchSessionItem newOrchSession = addSessionCaptor.getAllValues().get(1);

                assertNotEquals(updatedPreviousSession.getSessionId(), orchSession.getSessionId());
                assertNotEquals(
                        updatedPreviousSession.getSessionId(), newOrchSession.getSessionId());
                assertTrue(
                        updatedPreviousSession.getTimeToLive()
                                < timeNow + configService.getSessionExpiry() + 100);
                assertTrue(
                        updatedPreviousSession.getTimeToLive()
                                > timeNow + configService.getSessionExpiry() - 100);
                assertTrue(updatedPreviousSession.getAuthenticated());
                assertEquals(updatedPreviousSession.getAuthTime(), authTime);

                verify(orchSessionService).deleteSession(orchSession.getSessionId());

                assertEquals(newOrchSession.getSessionId(), newSessionId);
                assertTrue(
                        newOrchSession.getTimeToLive()
                                < timeNow + configService.getSessionExpiry() + 100);
                assertTrue(
                        newOrchSession.getTimeToLive()
                                > timeNow + configService.getSessionExpiry() - 100);
                assertFalse(newOrchSession.getAuthenticated());
                assertEquals(
                        newOrchSession.getPreviousSessionId(),
                        updatedPreviousSession.getSessionId());
            } else {
                verify(orchSessionService, times(1)).addSession(addSessionCaptor.capture());
                OrchSessionItem updatedSession = addSessionCaptor.getAllValues().get(0);

                assertEquals(NEW_SESSION_ID, newSessionId);
                assertEquals(NEW_SESSION_ID, updatedSession.getSessionId());
                assertTrue(updatedSession.getAuthenticated());
                assertEquals(updatedSession.getAuthTime(), authTime);
                assertTrue(
                        updatedSession.getTimeToLive()
                                < timeNow + configService.getSessionExpiry() + 100);
                assertTrue(
                        updatedSession.getTimeToLive()
                                > timeNow + configService.getSessionExpiry() - 100);

                verify(orchSessionService).deleteSession(orchSession.getSessionId());
            }
        }

        @ParameterizedTest
        @MethodSource("authTimeAndMaxAgeParams")
        void shouldUpdateOrchSessionCorrectlyForRequestObjectRequest(
                Long authTime, String maxAgeParam, boolean maxAgeExpired) throws JOSEException {
            when(clientService.getClient(anyString()))
                    .thenReturn(Optional.of(generateClientRegistry().withMaxAgeEnabled(true)));
            withExistingOrchSession(orchSession.withAuthenticated(true).withAuthTime(authTime));

            var jwtClaimsSet =
                    buildJwtClaimsSet("https://localhost/authorize", null, null, maxAgeParam);
            var event =
                    withRequestEvent(
                            Map.of(
                                    "client_id",
                                    CLIENT_ID.getValue(),
                                    "scope",
                                    "openid",
                                    "response_type",
                                    "code",
                                    "request",
                                    generateSignedJWT(jwtClaimsSet, RSA_KEY_PAIR).serialize()));

            var response = makeRequestWithSessionIdInCookie(event);
            var sessionCookie =
                    getHttpCookieFromMultiValueResponseHeaders(
                            response.getMultiValueHeaders(), "gs");
            var newSessionId = sessionCookie.get().getValue().split("\\.")[0];

            ArgumentCaptor<OrchSessionItem> addSessionCaptor =
                    ArgumentCaptor.forClass(OrchSessionItem.class);
            if (maxAgeExpired) {
                verify(orchSessionService, times(2)).addSession(addSessionCaptor.capture());
                OrchSessionItem updatedPreviousSession = addSessionCaptor.getAllValues().get(0);
                OrchSessionItem newOrchSession = addSessionCaptor.getAllValues().get(1);

                assertNotEquals(updatedPreviousSession.getSessionId(), orchSession.getSessionId());
                assertNotEquals(
                        updatedPreviousSession.getSessionId(), newOrchSession.getSessionId());
                assertTrue(
                        updatedPreviousSession.getTimeToLive()
                                < timeNow + configService.getSessionExpiry() + 100);
                assertTrue(
                        updatedPreviousSession.getTimeToLive()
                                > timeNow + configService.getSessionExpiry() - 100);
                assertTrue(updatedPreviousSession.getAuthenticated());
                assertEquals(updatedPreviousSession.getAuthTime(), authTime);

                verify(orchSessionService).deleteSession(orchSession.getSessionId());

                assertEquals(newOrchSession.getSessionId(), newSessionId);
                assertTrue(
                        newOrchSession.getTimeToLive()
                                < timeNow + configService.getSessionExpiry() + 100);
                assertTrue(
                        newOrchSession.getTimeToLive()
                                > timeNow + configService.getSessionExpiry() - 100);
                assertFalse(newOrchSession.getAuthenticated());
                assertEquals(
                        newOrchSession.getPreviousSessionId(),
                        updatedPreviousSession.getSessionId());
                assertEquals(0, newOrchSession.getProcessingIdentityAttempts());

            } else {
                verify(orchSessionService, times(1)).addSession(addSessionCaptor.capture());
                OrchSessionItem updatedSession = addSessionCaptor.getAllValues().get(0);

                assertEquals(NEW_SESSION_ID, newSessionId);
                assertEquals(NEW_SESSION_ID, updatedSession.getSessionId());
                assertTrue(updatedSession.getAuthenticated());
                assertEquals(updatedSession.getAuthTime(), authTime);
                assertTrue(
                        updatedSession.getTimeToLive()
                                < timeNow + configService.getSessionExpiry() + 100);
                assertTrue(
                        updatedSession.getTimeToLive()
                                > timeNow + configService.getSessionExpiry() - 100);
                assertEquals(0, updatedSession.getProcessingIdentityAttempts());

                verify(orchSessionService).deleteSession(orchSession.getSessionId());
            }
        }

        private APIGatewayProxyResponseEvent makeRequestWithSessionIdInCookie(
                APIGatewayProxyRequestEvent event) {
            event.withHeaders(Map.of("Cookie", SESSION_COOKIE));
            return makeHandlerRequest(event);
        }
    }

    @Nested
    class RPRateLimiting {

        @Test
        void shouldCallRateLimitService() {
            Map<String, String> requestParams = buildRequestParams(null);
            APIGatewayProxyRequestEvent event = withRequestEvent(requestParams);

            APIGatewayProxyResponseEvent response = makeHandlerRequest(event);
            URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));

            assertThat(response, hasStatus(302));
            assertThat(uri.getAuthority(), containsString(FRONT_END_AUTHORIZE_URI.getAuthority()));

            verify(rateLimitService)
                    .getClientRateLimitDecision(
                            argThat(
                                    clientRequestInfo ->
                                            clientRequestInfo
                                                            .clientID()
                                                            .equals(clientRegistry.getClientID())
                                                    && clientRequestInfo
                                                            .rateLimit()
                                                            .equals(
                                                                    clientRegistry
                                                                            .getRateLimit())));
        }
    }

    @Nested
    class ApprovalsTests {
        @Test
        void shouldSendAuthTheClaimsRequiredWhenIdentityRequested() {
            withExistingSession();
            var authRequestParams =
                    generateAuthRequest(Optional.of(jsonArrayOf("P2.Cl.Cm"))).toParameters();
            when(orchClientSession.getAuthRequestParams()).thenReturn(authRequestParams);
            APIGatewayProxyResponseEvent response;

            try (var ignored =
                    mockConstruction(
                            State.class,
                            (mock, context) -> {
                                when(mock.getValue()).thenReturn("state");
                            })) {
                response =
                        runWithIds(
                                () ->
                                        handler.handleRequest(
                                                withRequestEvent(
                                                        buildRequestParams(
                                                                Map.of("vtr", "[\"P2.Cl.Cm\"]"))),
                                                context),
                                List.of(
                                        NEW_CLIENT_SESSION_ID,
                                        NEW_SESSION_ID,
                                        NEW_BROWSER_SESSION_ID,
                                        "test-jti"));
            }

            URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));
            var jwtClaimSetCaptor = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService)
                    .getSignedAndEncryptedJWT(jwtClaimSetCaptor.capture());

            JsonApprovals.verifyAsJson(
                    jwtClaimSetCaptor.getValue().toJSONObject(), GsonBuilder::serializeNulls);
            assertThat(response, hasStatus(302));
            assertEquals(FRONT_END_BASE_URI.getAuthority(), uri.getAuthority());
        }

        @Test
        void shouldSendAuthTheRequiredClaimsWhenAuthOnly() {
            withExistingSession();
            var authRequestParams =
                    generateAuthRequest(Optional.of(jsonArrayOf("Cl.Cm"))).toParameters();
            when(orchClientSession.getAuthRequestParams()).thenReturn(authRequestParams);
            APIGatewayProxyResponseEvent response;

            try (var ignored =
                    mockConstruction(
                            State.class,
                            (mock, context) -> {
                                when(mock.getValue()).thenReturn("state");
                            })) {
                response =
                        runWithIds(
                                () ->
                                        handler.handleRequest(
                                                withRequestEvent(
                                                        buildRequestParams(
                                                                Map.of("vtr", "[\"Cl.Cm\"]"))),
                                                context),
                                List.of(
                                        NEW_CLIENT_SESSION_ID,
                                        NEW_SESSION_ID,
                                        NEW_BROWSER_SESSION_ID,
                                        "test-jti"));
            }

            URI uri = URI.create(response.getHeaders().get(ResponseHeaders.LOCATION));
            var jwtClaimSetCaptor = ArgumentCaptor.forClass(JWTClaimsSet.class);
            verify(orchestrationAuthorizationService)
                    .getSignedAndEncryptedJWT(jwtClaimSetCaptor.capture());

            JsonApprovals.verifyAsJson(
                    jwtClaimSetCaptor.getValue().toJSONObject(), GsonBuilder::serializeNulls);
            assertThat(response, hasStatus(302));
            assertEquals(FRONT_END_BASE_URI.getAuthority(), uri.getAuthority());
        }
    }

    private APIGatewayProxyResponseEvent makeHandlerRequest(APIGatewayProxyRequestEvent event) {
        var response =
                runWithIds(
                        () -> handler.handleRequest(event, context),
                        List.of(
                                NEW_CLIENT_SESSION_ID,
                                NEW_SESSION_ID,
                                NEW_BROWSER_SESSION_ID,
                                NEW_SESSION_ID_FOR_PREV_SESSION));

        verify(auditService)
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
        event.withHeaders(
                Map.of(
                        "txma-audit-encoded",
                        TXMA_ENCODED_HEADER_VALUE,
                        "Cookie",
                        format("%s;bsid=%s", SESSION_COOKIE, BROWSER_SESSION_ID)));
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
                        .nonce(NONCE);
        credentialTrustLevel.ifPresent(t -> builder.customParameter("vtr", t));
        return builder.build();
    }

    private void withExistingOrchSession(OrchSessionItem orchSession) {
        when(orchSessionService.getSession(any())).thenReturn(Optional.ofNullable(orchSession));
        when(orchSessionService.addOrUpdateSessionId(any(), any())).thenReturn(orchSession);
    }

    private void withExistingSession() {
        when(orchSessionService.getSession(any())).thenReturn(Optional.of(orchSession));
    }

    private void withNoSession() {
        when(orchSessionService.getSession(any())).thenReturn(Optional.empty());
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
                .withSubjectType("pairwise")
                .withIdentityVerificationSupported(true)
                .withMaxAgeEnabled(false);
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
                .claim("max_age", "1000")
                .claim("vtr", "[Cl.Cm]")
                .build();
    }

    private static JWTClaimsSet buildJwtClaimsSet(
            String audience, String prompt, String idToken, String maxAge) {
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
                .claim("max_age", maxAge)
                .build();
    }

    private void verifyAuthorisationRequestParsedAuditEvent() {
        verifyAuthorisationRequestParsedAuditEvent(Map.of());
    }

    private void verifyAuthorisationRequestParsedAuditEvent(
            Map<String, Object> extraOrSubstituteMetadata) {
        Map<String, Object> metadataPairs = new HashMap<>();
        metadataPairs.put("rpSid", AuditService.UNKNOWN);
        metadataPairs.put("identityRequested", false);
        metadataPairs.put("reauthRequested", false);
        metadataPairs.put("credential_trust_level", "MEDIUM_LEVEL");
        metadataPairs.putAll(extraOrSubstituteMetadata);
        AuditService.MetadataPair[] expectedMetadataPairs =
                metadataPairs.entrySet().stream()
                        .map(entry -> pair(entry.getKey(), entry.getValue()))
                        .toArray(AuditService.MetadataPair[]::new);
        ArgumentCaptor<AuditService.MetadataPair[]> metadataPairCaptor =
                ArgumentCaptor.forClass(AuditService.MetadataPair[].class);

        verify(auditService)
                .submitAuditEvent(
                        eq(OidcAuditableEvent.AUTHORISATION_REQUEST_PARSED),
                        eq(CLIENT_ID.getValue()),
                        eq(BASE_AUDIT_USER),
                        metadataPairCaptor.capture());

        assertThat(
                Arrays.asList(metadataPairCaptor.getValue()),
                containsInAnyOrder(expectedMetadataPairs));
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
