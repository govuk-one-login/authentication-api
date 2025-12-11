package uk.gov.di.orchestration.shared.services;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.MockedStatic;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.api.AuthFrontend;
import uk.gov.di.orchestration.shared.entity.AccountIntervention;
import uk.gov.di.orchestration.shared.entity.AccountInterventionState;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.DestroySessionsRequest;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.helpers.IpAddressHelper;
import uk.gov.di.orchestration.shared.helpers.NowHelper.NowClock;
import uk.gov.di.orchestration.shared.helpers.PersistentIdHelper;
import uk.gov.di.orchestration.sharedtest.helper.TokenGeneratorHelper;

import java.net.URI;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.time.Clock.fixed;
import static java.time.ZoneId.systemDefault;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.domain.LogoutAuditableEvent.LOG_OUT_SUCCESS;
import static uk.gov.di.orchestration.shared.entity.LogoutReason.MAX_AGE_EXPIRY;
import static uk.gov.di.orchestration.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.orchestration.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

// QualityGateUnitTest
class LogoutServiceTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final OrchSessionService orchSessionService = mock(OrchSessionService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final OrchClientSessionService orchClientSessionService =
            mock(OrchClientSessionService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final AuthFrontend authFrontend = mock(AuthFrontend.class);

    private final APIGatewayProxyRequestEvent event = mock(APIGatewayProxyRequestEvent.class);

    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final BackChannelLogoutService backChannelLogoutService =
            mock(BackChannelLogoutService.class);

    private static MockedStatic<IpAddressHelper> ipAddressHelper;
    private static MockedStatic<PersistentIdHelper> persistentIdHelper;
    private static MockedStatic<ClientSubjectHelper> clientSubjectHelper;

    private static final State STATE = new State();
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final String SESSION_ID = IdGenerator.generate();
    private static final String CLIENT_SESSION_ID = IdGenerator.generate();
    private static final String ARBITRARY_UNIX_TIMESTAMP = "1700558480962";
    private static final String IP_ADDRESS = "123.123.123.123";
    private static final String PERSISTENT_SESSION_ID =
            IdGenerator.generate() + "--" + ARBITRARY_UNIX_TIMESTAMP;
    private static final URI DEFAULT_LOGOUT_URI =
            URI.create("https://signin.test.account.gov.uk/signed-out");
    private static final ErrorObject ERROR_OBJECT =
            new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, "invalid session");
    private static final URI ERROR_LOGOUT_URI =
            URI.create(
                    "https://signin.test.account.gov.uk/signed-out?error_code=invalid_request&error_description=invalid%20session");
    private static final URI SUSPENDED_LOGOUT_URI =
            URI.create("https://signin.test.account.gov.uk/unavailable-temporary");
    private static final URI BLOCKED_LOGOUT_URI =
            URI.create("https://signin.test.account.gov.uk/unavailable-permanent");
    private static final URI CLIENT_LOGOUT_URI = URI.create("http://localhost/logout");
    private static final String CLIENT_ID = "client-id";
    private static final Subject SUBJECT = new Subject();
    private static OrchSessionItem orchSession;

    private static final String FRONTEND_BASE_URL = "https://signin.test.account.gov.uk/";
    private static final URI REAUTH_FAILURE_URI =
            URI.create("https://redirect.go.uk?error=access_denied");

    private static final String ENVIRONMENT = "test";
    private SignedJWT signedIDToken;
    private Optional<String> audience;
    private Optional<String> rpPairwiseId;
    private LogoutService logoutService;
    private final TxmaAuditUser auditUser =
            TxmaAuditUser.user()
                    .withIpAddress(IP_ADDRESS)
                    .withSessionId(SESSION_ID)
                    .withPersistentSessionId(PERSISTENT_SESSION_ID)
                    .withUserId(SUBJECT.getValue());
    private final TxmaAuditUser auditUserWhenNoCookie =
            TxmaAuditUser.user()
                    .withIpAddress(IP_ADDRESS)
                    .withSessionId(SESSION_ID)
                    .withPersistentSessionId(null)
                    .withUserId(null);
    private DestroySessionsRequest destroySessionsRequest;

    @BeforeEach
    void setup() throws JOSEException, ParseException {
        ipAddressHelper = mockStatic(IpAddressHelper.class);
        persistentIdHelper = mockStatic(PersistentIdHelper.class);
        clientSubjectHelper = mockStatic(ClientSubjectHelper.class);
        when(IpAddressHelper.extractIpAddress(any())).thenReturn(IP_ADDRESS);
        when(PersistentIdHelper.extractPersistentIdFromCookieHeader(event.getHeaders()))
                .thenReturn(PERSISTENT_SESSION_ID);

        when(configurationService.getInternalSectorURI()).thenReturn(INTERNAL_SECTOR_URI);
        when(configurationService.getEnvironment()).thenReturn(ENVIRONMENT);

        when(authFrontend.defaultLogoutURI()).thenReturn(DEFAULT_LOGOUT_URI);
        when(authFrontend.errorLogoutURI(ERROR_OBJECT)).thenReturn(ERROR_LOGOUT_URI);
        when(authFrontend.accountSuspendedURI()).thenReturn(SUSPENDED_LOGOUT_URI);
        when(authFrontend.accountBlockedURI()).thenReturn(BLOCKED_LOGOUT_URI);

        logoutService =
                new LogoutService(
                        orchSessionService,
                        dynamoClientService,
                        orchClientSessionService,
                        auditService,
                        cloudwatchMetricsService,
                        backChannelLogoutService,
                        authFrontend,
                        new NowClock(Clock.systemUTC()));

        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        signedIDToken =
                TokenGeneratorHelper.generateIDToken(
                        CLIENT_ID, SUBJECT, "http://localhost-rp", ecSigningKey);
        SignedJWT idToken = SignedJWT.parse(signedIDToken.serialize());
        audience = idToken.getJWTClaimsSet().getAudience().stream().findFirst();
        rpPairwiseId = Optional.of(idToken.getJWTClaimsSet().getSubject());

        orchSession = new OrchSessionItem(SESSION_ID);
        setUpClientSession(CLIENT_SESSION_ID, CLIENT_ID, rpPairwiseId.get());
        when(orchSessionService.getSession(anyString())).thenReturn(Optional.of(orchSession));
        destroySessionsRequest = new DestroySessionsRequest(SESSION_ID, List.of(CLIENT_SESSION_ID));
    }

    @AfterEach
    void teardown() {
        ipAddressHelper.close();
        persistentIdHelper.close();
        clientSubjectHelper.close();
    }

    // QualityGateRegressionTest
    @Test
    void successfullyReturnsClientLogoutResponse() {
        APIGatewayProxyResponseEvent response =
                logoutService.handleLogout(
                        Optional.of(destroySessionsRequest),
                        Optional.empty(),
                        Optional.of(CLIENT_LOGOUT_URI),
                        Optional.of(STATE.getValue()),
                        auditUser,
                        Optional.of(audience.get()),
                        rpPairwiseId);

        verify(orchClientSessionService)
                .deleteStoredClientSession(orchSession.getClientSessions().get(0));
        verify(orchSessionService).deleteSession(SESSION_ID);
        verify(auditService)
                .submitAuditEvent(
                        LOG_OUT_SUCCESS,
                        CLIENT_ID,
                        auditUser,
                        pair("logoutReason", "front-channel"),
                        pair("rpPairwiseId", rpPairwiseId.get()));
        verify(backChannelLogoutService)
                .sendLogoutMessage(argThat(withClientId("client-id")), eq(rpPairwiseId.get()));
        verify(cloudwatchMetricsService).incrementLogout(Optional.of(CLIENT_ID));

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(CLIENT_LOGOUT_URI + "?state=" + STATE));
    }

    // QualityGateRegressionTest
    @Test
    void successfullyReturnsLogoutResponseWithoutStateWhenStateIsAbsent() {
        APIGatewayProxyResponseEvent response =
                logoutService.handleLogout(
                        Optional.of(destroySessionsRequest),
                        Optional.empty(),
                        Optional.empty(),
                        Optional.empty(),
                        auditUser,
                        audience,
                        rpPairwiseId);

        verify(orchClientSessionService)
                .deleteStoredClientSession(orchSession.getClientSessions().get(0));
        verify(orchSessionService).deleteSession(SESSION_ID);
        verify(auditService)
                .submitAuditEvent(
                        LOG_OUT_SUCCESS,
                        CLIENT_ID,
                        auditUser,
                        pair("logoutReason", "front-channel"),
                        pair("rpPairwiseId", rpPairwiseId.get()));
        verify(backChannelLogoutService)
                .sendLogoutMessage(argThat(withClientId("client-id")), eq(rpPairwiseId.get()));
        verify(cloudwatchMetricsService).incrementLogout(Optional.of(CLIENT_ID));

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(DEFAULT_LOGOUT_URI.toString()));
    }

    // QualityGateRegressionTest
    @Test
    void successfullyReturnsDefaultLogoutResponseWithStateWhenStateIsPresent() {
        APIGatewayProxyResponseEvent response =
                logoutService.handleLogout(
                        Optional.of(destroySessionsRequest),
                        Optional.empty(),
                        Optional.empty(),
                        Optional.of(STATE.getValue()),
                        auditUser,
                        audience,
                        rpPairwiseId);

        verify(orchClientSessionService)
                .deleteStoredClientSession(orchSession.getClientSessions().get(0));
        verify(orchSessionService).deleteSession(SESSION_ID);
        verify(auditService)
                .submitAuditEvent(
                        LOG_OUT_SUCCESS,
                        CLIENT_ID,
                        auditUser,
                        pair("logoutReason", "front-channel"),
                        pair("rpPairwiseId", rpPairwiseId.get()));
        verify(backChannelLogoutService)
                .sendLogoutMessage(argThat(withClientId("client-id")), eq(rpPairwiseId.get()));
        verify(cloudwatchMetricsService).incrementLogout(Optional.of(CLIENT_ID));

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(DEFAULT_LOGOUT_URI + "?state=" + STATE.getValue()));
    }

    // QualityGateRegressionTest
    @Test
    void successfullyReturnsErrorLogoutResponse() {
        var errorObject = new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, "invalid session");
        APIGatewayProxyResponseEvent response =
                logoutService.handleLogout(
                        Optional.of(destroySessionsRequest),
                        Optional.of(errorObject),
                        Optional.empty(),
                        Optional.empty(),
                        auditUser,
                        Optional.of(CLIENT_ID),
                        rpPairwiseId);

        verify(orchClientSessionService)
                .deleteStoredClientSession(orchSession.getClientSessions().get(0));
        verify(orchSessionService).deleteSession(SESSION_ID);
        verify(auditService)
                .submitAuditEvent(
                        LOG_OUT_SUCCESS,
                        CLIENT_ID,
                        auditUser,
                        pair("logoutReason", "front-channel"),
                        pair("rpPairwiseId", rpPairwiseId.get()));
        verify(backChannelLogoutService)
                .sendLogoutMessage(argThat(withClientId("client-id")), eq(rpPairwiseId.get()));
        verify(cloudwatchMetricsService).incrementLogout(Optional.of(CLIENT_ID));

        assertThat(response, hasStatus(302));

        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(ERROR_LOGOUT_URI.toString()));
    }

    // QualityGateRegressionTest
    @Test
    void doseNotIncrementLogoutMetricIfSessionNotPresent() {
        logoutService.handleLogout(
                Optional.empty(),
                Optional.empty(),
                Optional.of(CLIENT_LOGOUT_URI),
                Optional.of(STATE.getValue()),
                auditUser,
                Optional.of(audience.get()),
                rpPairwiseId);

        verifyNoInteractions(cloudwatchMetricsService);
    }

    // QualityGateRegressionTest
    @Test
    void destroysSessionsAndReturnsAccountInterventionLogoutResponseWhenAccountIsBlocked() {
        AccountIntervention intervention =
                new AccountIntervention(new AccountInterventionState(true, false, false, false));
        APIGatewayProxyResponseEvent response =
                logoutService.handleAccountInterventionLogout(
                        new DestroySessionsRequest(SESSION_ID, List.of(CLIENT_SESSION_ID)),
                        SUBJECT.getValue(),
                        event,
                        CLIENT_ID,
                        intervention);

        verify(orchClientSessionService)
                .deleteStoredClientSession(orchSession.getClientSessions().get(0));
        verify(orchSessionService).deleteSession(SESSION_ID);
        verify(auditService)
                .submitAuditEvent(
                        LOG_OUT_SUCCESS,
                        CLIENT_ID,
                        auditUser,
                        pair("logoutReason", "intervention"));
        verify(backChannelLogoutService)
                .sendLogoutMessage(argThat(withClientId("client-id")), eq(rpPairwiseId.get()));
        verify(cloudwatchMetricsService)
                .incrementLogout(Optional.of(CLIENT_ID), Optional.of(intervention));

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(FRONTEND_BASE_URL + "unavailable-permanent"));
    }

    // QualityGateRegressionTest
    @Test
    void destroysSessionsAndReturnsAccountInterventionLogoutResponseWhenAccountIsSuspended() {
        AccountIntervention intervention =
                new AccountIntervention(new AccountInterventionState(false, true, false, false));

        APIGatewayProxyResponseEvent response =
                logoutService.handleAccountInterventionLogout(
                        new DestroySessionsRequest(SESSION_ID, List.of(CLIENT_SESSION_ID)),
                        SUBJECT.getValue(),
                        event,
                        CLIENT_ID,
                        intervention);

        verify(orchClientSessionService)
                .deleteStoredClientSession(orchSession.getClientSessions().get(0));
        verify(orchSessionService).deleteSession(SESSION_ID);
        verify(auditService)
                .submitAuditEvent(
                        LOG_OUT_SUCCESS,
                        CLIENT_ID,
                        auditUser,
                        pair("logoutReason", "intervention"));
        verify(backChannelLogoutService)
                .sendLogoutMessage(argThat(withClientId("client-id")), eq(rpPairwiseId.get()));
        verify(cloudwatchMetricsService)
                .incrementLogout(Optional.of(CLIENT_ID), Optional.of(intervention));

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(FRONTEND_BASE_URL + "unavailable-temporary"));
    }

    // QualityGateRegressionTest
    @Test
    void shouldDeleteSessionFromDynamoWhenNoCookieExists() {
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setQueryStringParameters(
                Map.of(
                        "post_logout_redirect_uri",
                        CLIENT_LOGOUT_URI.toString(),
                        "state",
                        STATE.toString()));
        input.setRequestContext(contextWithSourceIp("123.123.123.123"));

        logoutService.handleLogout(
                Optional.of(destroySessionsRequest),
                Optional.empty(),
                Optional.of(CLIENT_LOGOUT_URI),
                Optional.of(STATE.getValue()),
                auditUserWhenNoCookie,
                Optional.empty(),
                rpPairwiseId);

        verify(orchClientSessionService)
                .deleteStoredClientSession(orchSession.getClientSessions().get(0));
        verify(orchSessionService).deleteSession(SESSION_ID);
        verify(backChannelLogoutService)
                .sendLogoutMessage(argThat(withClientId("client-id")), eq(rpPairwiseId.get()));
        verify(cloudwatchMetricsService).incrementLogout(Optional.empty());
        verify(auditService)
                .submitAuditEvent(
                        LOG_OUT_SUCCESS,
                        AuditService.UNKNOWN,
                        auditUserWhenNoCookie,
                        pair("logoutReason", "front-channel"),
                        pair("rpPairwiseId", rpPairwiseId.get()));
    }

    // QualityGateRegressionTest
    @Test
    void throwsWhenGenerateAccountInterventionLogoutResponseCalledInappropriately() {
        AccountIntervention intervention =
                new AccountIntervention(new AccountInterventionState(false, false, false, false));

        var expectedDestroySessionsRequest =
                new DestroySessionsRequest(SESSION_ID, List.of(CLIENT_SESSION_ID));
        var expectedInternalCommonSubjectId = SUBJECT.getValue();
        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () ->
                                logoutService.handleAccountInterventionLogout(
                                        expectedDestroySessionsRequest,
                                        expectedInternalCommonSubjectId,
                                        event,
                                        CLIENT_ID,
                                        intervention),
                        "Expected to throw exception");

        assertEquals("Account status must be blocked or suspended", exception.getMessage());
    }

    // QualityGateRegressionTest
    @Test
    void includesRpPairwiseIdInLogOutSuccessAuditEventWhenItIsAvailable() {

        logoutService.handleLogout(
                Optional.of(destroySessionsRequest),
                Optional.empty(),
                Optional.of(CLIENT_LOGOUT_URI),
                Optional.of(STATE.getValue()),
                auditUser,
                Optional.of(audience.get()),
                rpPairwiseId);

        verify(auditService)
                .submitAuditEvent(
                        LOG_OUT_SUCCESS,
                        CLIENT_ID,
                        auditUser,
                        pair("logoutReason", "front-channel"),
                        pair("rpPairwiseId", rpPairwiseId.get()));
    }

    // QualityGateRegressionTest
    @Test
    void sessionsAreAllDeletedOnLogout() {
        setupAdditionalClientSessions();

        APIGatewayProxyResponseEvent response =
                logoutService.handleLogout(
                        Optional.of(destroySessionsRequest),
                        Optional.empty(),
                        Optional.of(CLIENT_LOGOUT_URI),
                        Optional.of(STATE.getValue()),
                        auditUser,
                        Optional.of(audience.get()),
                        rpPairwiseId);

        verify(orchClientSessionService)
                .deleteStoredClientSession(orchSession.getClientSessions().get(0));
        verify(orchClientSessionService).deleteStoredClientSession("client-session-id-2");
        verify(orchClientSessionService).deleteStoredClientSession("client-session-id-3");
        verify(orchSessionService).deleteSession(SESSION_ID);
        verify(auditService)
                .submitAuditEvent(
                        LOG_OUT_SUCCESS,
                        CLIENT_ID,
                        auditUser,
                        pair("logoutReason", "front-channel"),
                        pair("rpPairwiseId", rpPairwiseId.get()));
        verify(backChannelLogoutService)
                .sendLogoutMessage(argThat(withClientId("client-id")), eq(rpPairwiseId.get()));
        verify(backChannelLogoutService)
                .sendLogoutMessage(
                        argThat(withClientId("client-id-2")), eq("rp-pairwise-id-client-2"));
        verify(backChannelLogoutService)
                .sendLogoutMessage(
                        argThat(withClientId("client-id-3")), eq("rp-pairwise-id-client-3"));
        verify(backChannelLogoutService, never())
                .sendLogoutMessage(argThat(withClientId("client-id-4")), anyString());
        verify(cloudwatchMetricsService).incrementLogout(Optional.of(CLIENT_ID));

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(CLIENT_LOGOUT_URI + "?state=" + STATE));
    }

    public static ArgumentMatcher<ClientRegistry> withClientId(String clientId) {
        return new ArgumentMatcher<>() {
            @Override
            public boolean matches(ClientRegistry argument) {
                return clientId.equals(argument.getClientID());
            }

            @Override
            public String toString() {
                return "a ClientRegistry with client_id " + clientId;
            }
        };
    }

    // QualityGateRegressionTest
    @Test
    void successfullyLogsOutAndGeneratesRedirectResponseForeReauthenticationFailure() {
        var response =
                logoutService.handleReauthenticationFailureLogout(
                        new DestroySessionsRequest(SESSION_ID, List.of(CLIENT_SESSION_ID)),
                        SUBJECT.getValue(),
                        event,
                        CLIENT_ID,
                        REAUTH_FAILURE_URI);

        verify(orchClientSessionService)
                .deleteStoredClientSession(orchSession.getClientSessions().get(0));
        verify(orchSessionService).deleteSession(SESSION_ID);
        verify(backChannelLogoutService)
                .sendLogoutMessage(argThat(withClientId("client-id")), eq(rpPairwiseId.get()));
        verify(cloudwatchMetricsService).incrementLogout(Optional.of(CLIENT_ID));
        verify(auditService)
                .submitAuditEvent(
                        LOG_OUT_SUCCESS,
                        CLIENT_ID,
                        auditUser,
                        pair("logoutReason", "reauthentication-failure"));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                is(equalTo(REAUTH_FAILURE_URI.toString())));
    }

    // QualityGateRegressionTest
    @Test
    void handlesAMaxAgeSessionExpiry() {
        var clientSessionId1 = IdGenerator.generate();
        var clientSessionId2 = IdGenerator.generate();
        var clientId1 = CLIENT_ID + "1";
        var clientId2 = CLIENT_ID + "2";
        var destroySessionsRequestForClients =
                new DestroySessionsRequest(SESSION_ID, List.of(clientSessionId1, clientSessionId2));

        var authTime = Instant.parse("2025-01-23T15:00:00Z");
        var previousOrchSession =
                new OrchSessionItem(SESSION_ID).withAuthTime(authTime.getEpochSecond());
        setUpClientSession(clientSessionId1, clientId1, "rp-pairwise-id-client-1");
        setUpClientSession(clientSessionId2, clientId2, "rp-pairwise-id-client-2");

        var logoutTime = authTime.plus(3600, ChronoUnit.SECONDS);
        var clock = fixed(logoutTime, systemDefault());
        logoutServiceWithClock(clock)
                .handleMaxAgeLogout(
                        destroySessionsRequestForClients, previousOrchSession, auditUser);

        verify(orchClientSessionService, times(1)).deleteStoredClientSession(clientSessionId1);
        verify(orchClientSessionService, times(1)).deleteStoredClientSession(clientSessionId2);
        verify(orchSessionService).deleteSession(SESSION_ID);
        verify(backChannelLogoutService)
                .sendLogoutMessage(argThat(withClientId(clientId1)), eq("rp-pairwise-id-client-1"));
        verify(backChannelLogoutService)
                .sendLogoutMessage(argThat(withClientId(clientId2)), eq("rp-pairwise-id-client-2"));
        var expectedExtensions = new ArrayList<AuditService.MetadataPair>();
        expectedExtensions.add(pair("logoutReason", MAX_AGE_EXPIRY.getValue()));
        expectedExtensions.add(pair("sessionAge", 3600));
        verify(auditService)
                .submitAuditEvent(
                        LOG_OUT_SUCCESS,
                        AuditService.UNKNOWN,
                        auditUser,
                        expectedExtensions.toArray(AuditService.MetadataPair[]::new));
    }

    // QualityGateRegressionTest
    @Test
    void handlesASessionInvalidatedLogout() {
        APIGatewayProxyResponseEvent response =
                logoutService.handleSessionInvalidationLogout(
                        new DestroySessionsRequest(SESSION_ID, List.of(CLIENT_SESSION_ID)),
                        SUBJECT.getValue(),
                        event,
                        CLIENT_ID);

        verify(orchClientSessionService)
                .deleteStoredClientSession(orchSession.getClientSessions().get(0));
        verify(orchSessionService).deleteSession(SESSION_ID);
        verify(auditService)
                .submitAuditEvent(
                        LOG_OUT_SUCCESS,
                        CLIENT_ID,
                        auditUser,
                        pair("logoutReason", "intervention"));
        verify(backChannelLogoutService)
                .sendLogoutMessage(argThat(withClientId("client-id")), eq(rpPairwiseId.get()));

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(FRONTEND_BASE_URL + "signed-out"));
    }

    private LogoutService logoutServiceWithClock(Clock clock) {
        return new LogoutService(
                orchSessionService,
                dynamoClientService,
                orchClientSessionService,
                auditService,
                cloudwatchMetricsService,
                backChannelLogoutService,
                authFrontend,
                new NowClock(clock));
    }

    private void setupAdditionalClientSessions() {
        setUpClientSession("client-session-id-2", "client-id-2", "rp-pairwise-id-client-2");
        setUpClientSession("client-session-id-3", "client-id-3", "rp-pairwise-id-client-3");
        setupClientSessionToken(signedIDToken);
        destroySessionsRequest =
                new DestroySessionsRequest(
                        SESSION_ID,
                        List.of(
                                CLIENT_SESSION_ID,
                                "client-session-id-2",
                                "client-session-id-3",
                                "client-session-id-4"));
    }

    private void setupClientSessionToken(JWT idToken) {
        var clientId = "client-id";
        var authRequestParams =
                Map.of(
                        "client_id",
                        List.of(clientId),
                        "redirect_uri",
                        List.of("http://localhost:8080"),
                        "scope",
                        List.of("email openid profile"),
                        "response_type",
                        List.of("code"),
                        "state",
                        List.of("some-state"));
        var creationTime = LocalDateTime.now();
        var orchClientSession =
                new OrchClientSessionItem(
                        clientId,
                        authRequestParams,
                        creationTime,
                        List.of(VectorOfTrust.getDefaults()),
                        "client_name");
        orchClientSession.setIdTokenHint(idToken.serialize());
        orchClientSession.setRpPairwiseId(rpPairwiseId.get());
        when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(orchClientSession));
    }

    private void setUpClientSession(String clientSessionId, String clientId, String rpPairwiseId) {
        orchSession.getClientSessions().add(clientSessionId);
        var creationDate = LocalDateTime.now();
        when(orchClientSessionService.getClientSession(clientSessionId))
                .thenReturn(
                        Optional.of(
                                new OrchClientSessionItem(
                                                clientSessionId,
                                                Map.of("client_id", List.of(clientId)),
                                                creationDate,
                                                List.of(VectorOfTrust.getDefaults()),
                                                "client_name")
                                        .withRpPairwiseId(rpPairwiseId)));
        when(dynamoClientService.getClient(clientId))
                .thenReturn(Optional.of(new ClientRegistry().withClientID(clientId)));
    }
}
