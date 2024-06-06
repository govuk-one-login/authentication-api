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
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.MockedStatic;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.entity.AccountIntervention;
import uk.gov.di.orchestration.shared.entity.AccountInterventionState;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.entity.UserProfile;
import uk.gov.di.orchestration.shared.entity.VtrList;
import uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.helpers.IpAddressHelper;
import uk.gov.di.orchestration.shared.helpers.PersistentIdHelper;
import uk.gov.di.orchestration.sharedtest.helper.TokenGeneratorHelper;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.domain.LogoutAuditableEvent.LOG_OUT_SUCCESS;
import static uk.gov.di.orchestration.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class LogoutServiceTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);

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
            URI.create("https://di-authentication-frontend.london.cloudapps.digital/signed-out");
    private static final URI CLIENT_LOGOUT_URI = URI.create("http://localhost/logout");
    private static final URI AI_LOGOUT_URI =
            URI.create("https://oidc.sandpit.account.gov.uk/orch-frontend/not-available");
    private static final String CLIENT_ID = "client-id";
    private static final Subject SUBJECT = new Subject();
    private static final String EMAIL = "joe.bloggs@test.com";

    private static final String OIDC_API_BASE_URL = "https://oidc.test.account.gov.uk/";
    private static final String FRONTEND_BASE_URL = "https://signin.test.account.gov.uk/";

    private static final String ENVIRONMENT = "test";

    private static final UserProfile USER_PROFILE =
            new UserProfile().withSubjectID("any").withSalt(ByteBuffer.allocateDirect(12345));

    private SignedJWT signedIDToken;
    private Optional<String> audience;
    private Optional<String> rpPairwiseId;
    private Session session;
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

    @BeforeEach
    void setup() throws JOSEException, ParseException {
        ipAddressHelper = mockStatic(IpAddressHelper.class);
        persistentIdHelper = mockStatic(PersistentIdHelper.class);
        clientSubjectHelper = mockStatic(ClientSubjectHelper.class);
        when(IpAddressHelper.extractIpAddress(any())).thenReturn(IP_ADDRESS);
        when(PersistentIdHelper.extractPersistentIdFromCookieHeader(event.getHeaders()))
                .thenReturn(PERSISTENT_SESSION_ID);

        when(configurationService.getDefaultLogoutURI()).thenReturn(DEFAULT_LOGOUT_URI);
        when(configurationService.getInternalSectorURI()).thenReturn(INTERNAL_SECTOR_URI);
        when(configurationService.getOidcApiBaseURL()).thenReturn(Optional.of(OIDC_API_BASE_URL));
        when(configurationService.getEnvironment()).thenReturn(ENVIRONMENT);
        when(configurationService.getFrontendBaseURL()).thenReturn(FRONTEND_BASE_URL);
        when(configurationService.getAccountStatusBlockedURI()).thenCallRealMethod();
        when(configurationService.getAccountStatusSuspendedURI()).thenCallRealMethod();
        logoutService =
                new LogoutService(
                        configurationService,
                        sessionService,
                        dynamoClientService,
                        clientSessionService,
                        auditService,
                        cloudwatchMetricsService,
                        backChannelLogoutService);

        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        signedIDToken =
                TokenGeneratorHelper.generateIDToken(
                        CLIENT_ID, SUBJECT, "http://localhost-rp", ecSigningKey);
        SignedJWT idToken = SignedJWT.parse(signedIDToken.serialize());
        audience = idToken.getJWTClaimsSet().getAudience().stream().findFirst();
        rpPairwiseId = Optional.of(idToken.getJWTClaimsSet().getSubject());

        session =
                generateSession()
                        .setEmailAddress(EMAIL)
                        .setInternalCommonSubjectIdentifier(SUBJECT.getValue());
    }

    @AfterEach
    void teardown() {
        ipAddressHelper.close();
        persistentIdHelper.close();
        clientSubjectHelper.close();
    }

    @Test
    void successfullyReturnsClientLogoutResponse() {
        APIGatewayProxyResponseEvent response =
                logoutService.generateLogoutResponse(
                        CLIENT_LOGOUT_URI,
                        Optional.of(STATE.getValue()),
                        Optional.empty(),
                        auditUser,
                        Optional.of(audience.get()),
                        rpPairwiseId);

        verify(auditService)
                .submitAuditEvent(
                        LOG_OUT_SUCCESS,
                        CLIENT_ID,
                        auditUser,
                        AuditService.MetadataPair.pair("rpPairwiseId", rpPairwiseId.get()));

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(CLIENT_LOGOUT_URI + "?state=" + STATE));
    }

    @Test
    void successfullyReturnsLogoutResponseWithoutStateWhenStateIsAbsent() {
        APIGatewayProxyResponseEvent response =
                logoutService.generateLogoutResponse(
                        configurationService.getDefaultLogoutURI(),
                        Optional.empty(),
                        Optional.empty(),
                        auditUser,
                        Optional.of(audience.get()),
                        rpPairwiseId);

        verify(auditService)
                .submitAuditEvent(
                        LOG_OUT_SUCCESS,
                        CLIENT_ID,
                        auditUser,
                        AuditService.MetadataPair.pair("rpPairwiseId", rpPairwiseId.get()));

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(DEFAULT_LOGOUT_URI.toString()));
    }

    @Test
    void successfullyReturnsDefaultLogoutResponseWithStateWhenStateIsPresent() {
        APIGatewayProxyResponseEvent response =
                logoutService.generateLogoutResponse(
                        configurationService.getDefaultLogoutURI(),
                        Optional.of(STATE.getValue()),
                        Optional.empty(),
                        auditUser,
                        Optional.of(audience.get()),
                        rpPairwiseId);

        verify(auditService)
                .submitAuditEvent(
                        LOG_OUT_SUCCESS,
                        CLIENT_ID,
                        auditUser,
                        AuditService.MetadataPair.pair("rpPairwiseId", rpPairwiseId.get()));

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(DEFAULT_LOGOUT_URI + "?state=" + STATE.getValue()));
    }

    @Test
    void successfullyReturnsErrorLogoutResponse() throws URISyntaxException {
        APIGatewayProxyResponseEvent response =
                logoutService.generateLogoutResponse(
                        configurationService.getDefaultLogoutURI(),
                        Optional.empty(),
                        Optional.of(
                                new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE, "invalid session")),
                        auditUser,
                        Optional.empty(),
                        rpPairwiseId);

        verify(auditService)
                .submitAuditEvent(
                        LOG_OUT_SUCCESS,
                        AuditService.UNKNOWN,
                        auditUser,
                        AuditService.MetadataPair.pair("rpPairwiseId", rpPairwiseId.get()));
        verifyNoInteractions(cloudwatchMetricsService);

        assertThat(response, hasStatus(302));
        ErrorObject errorObject =
                new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, "invalid session");
        URIBuilder uriBuilder = new URIBuilder(DEFAULT_LOGOUT_URI);
        uriBuilder.addParameter("error_code", errorObject.getCode());
        uriBuilder.addParameter("error_description", errorObject.getDescription());
        URI expectedUri = uriBuilder.build();
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(expectedUri.toString()));
    }

    @Test
    void destroysSessionsAndReturnsAccountInterventionLogoutResponseWhenAccountIsBlocked() {
        AccountIntervention intervention =
                new AccountIntervention(new AccountInterventionState(true, false, false, false));
        APIGatewayProxyResponseEvent response =
                logoutService.handleAccountInterventionLogout(
                        session, event, CLIENT_ID, intervention);

        verify(clientSessionService).deleteStoredClientSession(session.getClientSessions().get(0));
        verify(sessionService).deleteSessionFromRedis(session.getSessionId());
        verify(auditService).submitAuditEvent(LOG_OUT_SUCCESS, CLIENT_ID, auditUser);
        verify(cloudwatchMetricsService)
                .incrementLogout(Optional.of(CLIENT_ID), Optional.of(intervention));

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(FRONTEND_BASE_URL + "unavailable-permanent"));
    }

    @Test
    void destroysSessionsAndReturnsAccountInterventionLogoutResponseWhenAccountIsSuspended() {
        AccountIntervention intervention =
                new AccountIntervention(new AccountInterventionState(false, true, false, false));

        APIGatewayProxyResponseEvent response =
                logoutService.handleAccountInterventionLogout(
                        session, event, CLIENT_ID, intervention);

        verify(clientSessionService).deleteStoredClientSession(session.getClientSessions().get(0));
        verify(sessionService).deleteSessionFromRedis(session.getSessionId());
        verify(auditService).submitAuditEvent(LOG_OUT_SUCCESS, CLIENT_ID, auditUser);
        verify(cloudwatchMetricsService)
                .incrementLogout(Optional.of(CLIENT_ID), Optional.of(intervention));

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(FRONTEND_BASE_URL + "unavailable-temporary"));
    }

    @Test
    void shouldDeleteSessionFromRedisWhenNoCookieExists() {
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setQueryStringParameters(
                Map.of(
                        "post_logout_redirect_uri",
                        CLIENT_LOGOUT_URI.toString(),
                        "state",
                        STATE.toString()));
        input.setRequestContext(contextWithSourceIp("123.123.123.123"));

        logoutService.generateLogoutResponse(
                CLIENT_LOGOUT_URI,
                Optional.of(STATE.getValue()),
                Optional.empty(),
                auditUserWhenNoCookie,
                Optional.empty(),
                rpPairwiseId);

        verify(sessionService, times(0)).deleteSessionFromRedis(SESSION_ID);
        verifyNoInteractions(cloudwatchMetricsService);
        verify(auditService)
                .submitAuditEvent(
                        LOG_OUT_SUCCESS,
                        AuditService.UNKNOWN,
                        auditUserWhenNoCookie,
                        AuditService.MetadataPair.pair("rpPairwiseId", rpPairwiseId.get()));
    }

    @Test
    void sessionsAreDeletedWhenDestroySessionsIsCalled() {

        setupAdditionalClientSessions();

        logoutService.destroySessions(session);

        verify(backChannelLogoutService)
                .sendLogoutMessage(
                        argThat(withClientId("client-id-1")), eq(EMAIL), eq(INTERNAL_SECTOR_URI));
        verify(backChannelLogoutService)
                .sendLogoutMessage(
                        argThat(withClientId("client-id-2")), eq(EMAIL), eq(INTERNAL_SECTOR_URI));
        verify(backChannelLogoutService)
                .sendLogoutMessage(
                        argThat(withClientId("client-id-3")), eq(EMAIL), eq(INTERNAL_SECTOR_URI));

        verify(clientSessionService).deleteStoredClientSession("client-session-id-1");
        verify(clientSessionService).deleteStoredClientSession("client-session-id-2");
        verify(clientSessionService).deleteStoredClientSession("client-session-id-3");
        verify(sessionService, times(1)).deleteSessionFromRedis(SESSION_ID);
    }

    @Test
    void throwsWhenGenerateAccountInterventionLogoutResponseCalledInappropriately() {
        AccountIntervention intervention =
                new AccountIntervention(new AccountInterventionState(false, false, false, false));

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () ->
                                logoutService.handleAccountInterventionLogout(
                                        session, event, CLIENT_ID, intervention),
                        "Expected to throw exception");

        assertEquals("Account status must be blocked or suspended", exception.getMessage());
    }

    @Test
    void includesRpPairwiseIdInLogOutSuccessAuditEventWhenItIsAvailable() {

        logoutService.generateLogoutResponse(
                CLIENT_LOGOUT_URI,
                Optional.of(STATE.getValue()),
                Optional.empty(),
                auditUser,
                Optional.of(audience.get()),
                rpPairwiseId);

        verify(auditService)
                .submitAuditEvent(
                        LOG_OUT_SUCCESS,
                        CLIENT_ID,
                        auditUser,
                        AuditService.MetadataPair.pair("rpPairwiseId", rpPairwiseId.get()));
    }

    private Session generateSession() {
        return new Session(SESSION_ID).addClientSession(CLIENT_SESSION_ID);
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

    private void setupAdditionalClientSessions() {
        setUpClientSession("client-session-id-1", "client-id-1");
        setUpClientSession("client-session-id-2", "client-id-2");
        setUpClientSession("client-session-id-3", "client-id-3");
        generateSessionFromCookie(session);
        setupClientSessionToken(signedIDToken);
    }

    private void setUpClientSession(String clientSessionId, String clientId) {
        session.getClientSessions().add(clientSessionId);
        when(clientSessionService.getClientSession(clientSessionId))
                .thenReturn(
                        Optional.of(
                                new ClientSession(
                                        Map.of("client_id", List.of(clientId)),
                                        LocalDateTime.now(),
                                        VtrList.DEFAULT_VTR_LIST,
                                        "client_name")));
        when(dynamoClientService.getClient(clientId))
                .thenReturn(Optional.of(new ClientRegistry().withClientID(clientId)));
    }

    private void generateSessionFromCookie(Session session) {
        when(sessionService.getSessionFromSessionCookie(anyMap())).thenReturn(Optional.of(session));
    }

    private void setupClientSessionToken(JWT idToken) {
        ClientSession clientSession =
                new ClientSession(
                        Map.of(
                                "client_id",
                                List.of("client-id"),
                                "redirect_uri",
                                List.of("http://localhost:8080"),
                                "scope",
                                List.of("email,openid,profile"),
                                "response_type",
                                List.of("code"),
                                "state",
                                List.of("some-state")),
                        LocalDateTime.now(),
                        VtrList.DEFAULT_VTR_LIST,
                        "client_name");
        clientSession.setIdTokenHint(idToken.serialize());
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(clientSession));
    }
}
