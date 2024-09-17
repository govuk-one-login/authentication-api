package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.ClientStartInfo;
import uk.gov.di.authentication.frontendapi.entity.StartResponse;
import uk.gov.di.authentication.frontendapi.entity.UserStartInfo;
import uk.gov.di.authentication.frontendapi.services.StartService;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.sharedtest.helper.KeyPairHelper;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.frontendapi.lambda.StartHandler.REAUTHENTICATE_HEADER;
import static uk.gov.di.authentication.shared.lambda.BaseFrontendHandler.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class StartHandlerTest {

    public static final String TEST_CLIENT_ID = "test_client_id";
    public static final String TEST_CLIENT_NAME = "test_client_name";
    private static final String SESSION_ID = "some-session-id";
    public static final State STATE = new State();
    public static final URI REDIRECT_URL = URI.create("https://localhost/redirect");
    private static final Scope DOC_APP_SCOPE =
            new Scope(OIDCScopeValue.OPENID, CustomScopeValue.DOC_CHECKING_APP);
    private static final Nonce NONCE = new Nonce();
    private static final ClientID CLIENT_ID = new ClientID("test-id");
    private static final String AUDIENCE = "https://localhost/authorize";
    private static final Json objectMapper = SerializationService.getInstance();

    private StartHandler handler;
    private final Context context = mock(Context.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final StartService startService = mock(StartService.class);
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);
    private final UserContext userContext = mock(UserContext.class);
    private final ClientRegistry clientRegistry = mock(ClientRegistry.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final Session session = new Session(SESSION_ID);
    private final ClientSession clientSession = getClientSession();
    private final ClientSession docAppClientSession = getDocAppClientSession();
    private static final AuditContext AUDIT_CONTEXT =
            new AuditContext(
                    TEST_CLIENT_ID,
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    AuditService.UNKNOWN,
                    AuditService.UNKNOWN,
                    IP_ADDRESS,
                    AuditService.UNKNOWN,
                    DI_PERSISTENT_SESSION_ID,
                    Optional.of(ENCODED_DEVICE_DETAILS));

    @BeforeEach
    void beforeEach() {
        when(configurationService.isIdentityEnabled()).thenReturn(true);
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
        when(sessionService.getSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(new Session("session-id")));
        when(userContext.getClient()).thenReturn(Optional.of(clientRegistry));
        when(userContext.getClientSession()).thenReturn(clientSession);
        when(clientRegistry.getClientID()).thenReturn(TEST_CLIENT_ID);
        handler =
                new StartHandler(
                        clientSessionService,
                        sessionService,
                        auditService,
                        startService,
                        authSessionService,
                        configurationService);
    }

    private static Stream<Arguments> cookieConsentGaTrackingIdValues() {
        return Stream.of(
                Arguments.of(null, "some-ga-tracking-id"),
                Arguments.of("some-cookie-consent-value", null),
                Arguments.of(null, null),
                Arguments.of("some-cookie-consent-value", "some-ga-tracking-id"),
                Arguments.of(null, "some-ga-tracking-id"),
                Arguments.of("some-cookie-consent-value", null),
                Arguments.of(null, null),
                Arguments.of("some-cookie-consent-value", "some-ga-tracking-id"));
    }

    @ParameterizedTest
    @MethodSource("cookieConsentGaTrackingIdValues")
    void shouldReturn200WithStartResponse(String cookieConsentValue, String gaTrackingId)
            throws ParseException, Json.JsonException {
        var userStartInfo = getUserStartInfo(cookieConsentValue, gaTrackingId);
        usingStartServiceThatReturns(userContext, getClientStartInfo(), userStartInfo);
        when(startService.getGATrackingId(anyMap())).thenReturn(gaTrackingId);
        usingValidClientSession();
        usingValidSession();

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        StartResponse response = objectMapper.readValue(result.getBody(), StartResponse.class);

        assertThat(response.client(), equalTo(getClientStartInfo()));
        assertThat(response.user(), equalTo(userStartInfo));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_START_INFO_FOUND,
                        AUDIT_CONTEXT,
                        pair("internalSubjectId", AuditService.UNKNOWN));
    }

    @Test
    void shouldReturn200WhenDocCheckingAppUserIsPresent()
            throws ParseException, Json.JsonException {
        when(userContext.getClientSession()).thenReturn(docAppClientSession);
        when(configurationService.getDocAppDomain()).thenReturn(URI.create("https://doc-app"));
        var userStartInfo = new UserStartInfo(false, false, false, null, null, true, null, false);
        var clientStartInfo =
                new ClientStartInfo(
                        TEST_CLIENT_NAME,
                        DOC_APP_SCOPE.toStringList(),
                        "MANDATORY",
                        false,
                        REDIRECT_URL,
                        STATE,
                        false);
        usingStartServiceThatReturns(userContext, clientStartInfo, userStartInfo);
        usingValidDocAppClientSession();
        usingValidSession();

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}");
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        var response = objectMapper.readValue(result.getBody(), StartResponse.class);

        assertThat(response.client(), equalTo(clientStartInfo));
        assertThat(response.user(), equalTo(userStartInfo));

        verify(clientSessionService).updateStoredClientSession(anyString(), any());

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_START_INFO_FOUND,
                        AUDIT_CONTEXT,
                        pair("internalSubjectId", AuditService.UNKNOWN));
    }

    @Test
    void shouldReturn200WithAuthenticatedFalseWhenAReauthenticationJourney()
            throws ParseException, Json.JsonException {
        var userStartInfo = new UserStartInfo(false, false, false, null, null, false, null, false);
        usingStartServiceThatReturns(userContext, getClientStartInfo(), userStartInfo);
        usingValidSession();
        usingValidClientSession();

        var rpPairwiseIdForReauth = "some-pairwise-id-for-reauth";
        var previousSigninJourneyId = "some-signin-journey-id";

        var body =
                format(
                        """
               { "rp-pairwise-id-for-reauth": %s,
               "previous-govuk-signin-journey-id": %s }
                """,
                        rpPairwiseIdForReauth, previousSigninJourneyId);
        var event = apiRequestEventWithHeadersAndBody(headersWithReauthenticate("true"), body);
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        var response = objectMapper.readValue(result.getBody(), StartResponse.class);

        assertFalse(response.user().isAuthenticated());

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_START_INFO_FOUND,
                        AUDIT_CONTEXT,
                        pair("internalSubjectId", AuditService.UNKNOWN));
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_REAUTH_REQUESTED,
                        AUDIT_CONTEXT,
                        pair("previous_govuk_signin_journey_id", previousSigninJourneyId),
                        pair("rpPairwiseId", rpPairwiseIdForReauth));
    }

    @Test
    void checkAuditEventStillEmittedWhenTICFHeaderNotProvided() throws ParseException {
        var userStartInfo = new UserStartInfo(false, false, false, null, null, false, null, false);
        usingStartServiceThatReturns(userContext, getClientStartInfo(), userStartInfo);
        usingValidSession();
        usingValidClientSession();

        var headers = headersWithReauthenticate("true");
        headers.remove(TXMA_AUDIT_ENCODED_HEADER);
        var event = apiRequestEventWithHeadersAndBody(headers, "{}");

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_START_INFO_FOUND,
                        AUDIT_CONTEXT.withTxmaAuditEncoded(Optional.empty()),
                        pair("internalSubjectId", AuditService.UNKNOWN));
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_REAUTH_REQUESTED,
                        AUDIT_CONTEXT.withTxmaAuditEncoded(Optional.empty()));
    }

    @Test
    void shouldReturn200WithAuthenticatedTrueWhenReauthenticateHeaderNotSetToTrue()
            throws ParseException, Json.JsonException {
        var userStartInfo = new UserStartInfo(false, false, true, null, null, false, null, false);
        usingStartServiceThatReturns(userContext, getClientStartInfo(), userStartInfo);
        usingValidSession();
        usingValidClientSession();

        var event = apiRequestEventWithHeadersAndBody(headersWithReauthenticate("false"), "{}");
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        var response = objectMapper.readValue(result.getBody(), StartResponse.class);

        assertTrue(response.user().isAuthenticated());
        verify(auditService, never())
                .submitAuditEvent(
                        eq(FrontendAuditableEvent.AUTH_REAUTH_REQUESTED),
                        any(),
                        any(AuditService.MetadataPair[].class));
    }

    @Test
    void shouldReturn400WhenClientSessionIsNotFound() throws Json.JsonException {
        usingInvalidClientSession();
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));

        String expectedResponse = objectMapper.writeValueAsString(ErrorResponse.ERROR_1018);
        assertThat(result, hasBody(expectedResponse));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400WhenSessionIsNotFound() throws Json.JsonException {
        usingValidClientSession();
        usingInvalidSession();
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));

        String expectedResponse = objectMapper.writeValueAsString(ErrorResponse.ERROR_1000);
        assertThat(result, hasBody(expectedResponse));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400WhenBuildClientStartInfoThrowsException()
            throws ParseException, Json.JsonException {
        when(startService.buildUserContext(session, clientSession)).thenReturn(userContext);
        when(startService.buildClientStartInfo(userContext))
                .thenThrow(new ParseException("Unable to parse authentication request"));
        usingValidClientSession();
        usingValidSession();

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));

        String expectedResponse = objectMapper.writeValueAsString(ErrorResponse.ERROR_1038);
        assertThat(result, hasBody(expectedResponse));

        verifyNoInteractions(auditService);
    }

    private void usingValidClientSession() {
        when(clientSessionService.getClientSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(clientSession));
    }

    private void usingValidDocAppClientSession() {
        when(clientSessionService.getClientSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(docAppClientSession));
    }

    private void usingInvalidClientSession() {
        when(clientSessionService.getClientSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.empty());
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
        when(startService.validateSession(session, CLIENT_SESSION_ID)).thenReturn(session);
    }

    private void usingInvalidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap())).thenReturn(Optional.empty());
    }

    private ClientSession getClientSession() {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                responseType,
                                scope,
                                new ClientID(TEST_CLIENT_ID),
                                URI.create("http://localhost/redirect"))
                        .build();
        return new ClientSession(
                authRequest.toParameters(), null, mock(VectorOfTrust.class), TEST_CLIENT_NAME);
    }

    private ClientSession getDocAppClientSession() {
        try {
            var jwtClaimsSet =
                    new JWTClaimsSet.Builder()
                            .audience(AUDIENCE)
                            .subject(new Subject().getValue())
                            .claim("redirect_uri", REDIRECT_URL)
                            .claim("response_type", ResponseType.CODE.toString())
                            .claim("scope", DOC_APP_SCOPE.toString())
                            .claim("nonce", NONCE)
                            .claim("state", STATE)
                            .claim("client_id", CLIENT_ID)
                            .issuer(new ClientID("test-id").getValue())
                            .build();
            var jwsHeader = new JWSHeader(JWSAlgorithm.RS256);
            var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
            var signer = new RSASSASigner(KeyPairHelper.GENERATE_RSA_KEY_PAIR().getPrivate());
            signedJWT.sign(signer);
            var authRequest =
                    new AuthenticationRequest.Builder(
                                    ResponseType.CODE, DOC_APP_SCOPE, CLIENT_ID, REDIRECT_URL)
                            .state(STATE)
                            .nonce(new Nonce())
                            .requestObject(signedJWT)
                            .build();
            return new ClientSession(
                    authRequest.toParameters(),
                    LocalDateTime.now(),
                    mock(VectorOfTrust.class),
                    TEST_CLIENT_NAME);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    private ClientStartInfo getClientStartInfo() {
        Scope scope = new Scope(OIDCScopeValue.OPENID.getValue());

        return new ClientStartInfo(
                TEST_CLIENT_NAME,
                scope.toStringList(),
                "MANDATORY",
                false,
                REDIRECT_URL,
                STATE,
                false);
    }

    private UserStartInfo getUserStartInfo(String cookieConsent, String gaCrossDomainTrackingId) {
        return new UserStartInfo(
                false, false, true, cookieConsent, gaCrossDomainTrackingId, false, null, false);
    }

    private void usingStartServiceThatReturns(
            UserContext userContext, ClientStartInfo clientStartInfo, UserStartInfo userStartInfo)
            throws ParseException {
        when(startService.buildUserContext(eq(session), any())).thenReturn(userContext);
        when(startService.buildClientStartInfo(userContext)).thenReturn(clientStartInfo);
        when(startService.getGATrackingId(anyMap())).thenReturn(null);
        when(startService.getCookieConsentValue(anyMap(), anyString())).thenReturn(null);
        when(startService.buildUserStartInfo(
                        eq(userContext), any(), any(), anyBoolean(), anyBoolean(), any()))
                .thenReturn(userStartInfo);
    }

    private Map<String, String> headersWithReauthenticate(String reauthenticate) {
        Map<String, String> headers = new HashMap<>();
        headers.putAll(VALID_HEADERS);
        headers.put(REAUTHENTICATE_HEADER, reauthenticate);
        return headers;
    }
}
