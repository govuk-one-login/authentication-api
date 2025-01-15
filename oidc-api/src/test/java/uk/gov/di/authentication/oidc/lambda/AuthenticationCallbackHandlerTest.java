package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCError;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import uk.gov.di.authentication.oidc.domain.OidcAuditableEvent;
import uk.gov.di.authentication.oidc.domain.OrchestrationAuditableEvent;
import uk.gov.di.authentication.oidc.exceptions.AuthenticationCallbackValidationException;
import uk.gov.di.authentication.oidc.services.AuthenticationAuthorizationService;
import uk.gov.di.authentication.oidc.services.AuthenticationTokenService;
import uk.gov.di.authentication.oidc.services.InitiateIPVAuthorisationService;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.api.AuthFrontend;
import uk.gov.di.orchestration.shared.conditions.IdentityHelper;
import uk.gov.di.orchestration.shared.domain.AuditableEvent;
import uk.gov.di.orchestration.shared.entity.*;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.services.*;

import java.net.URI;
import java.util.*;
import java.util.stream.Stream;

import static com.nimbusds.oauth2.sdk.http.HTTPRequest.Method.GET;
import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static uk.gov.di.orchestration.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.orchestration.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.orchestration.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthenticationCallbackHandlerTest {
    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);
    private static final AuthenticationAuthorizationService authorizationService =
            mock(AuthenticationAuthorizationService.class);
    private final AuthenticationTokenService tokenService = mock(AuthenticationTokenService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final OrchSessionService orchSessionService = mock(OrchSessionService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final AuthenticationUserInfoStorageService userInfoStorageService =
            mock(AuthenticationUserInfoStorageService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private static final AuthorisationCodeService authorisationCodeService =
            mock(AuthorisationCodeService.class);
    private static final InitiateIPVAuthorisationService initiateIPVAuthorisationService =
            mock(InitiateIPVAuthorisationService.class);
    private static final AccountInterventionService accountInterventionService =
            mock(AccountInterventionService.class);
    private static final LogoutService logoutService = mock(LogoutService.class);
    private static final CookieHelper cookieHelper = mock(CookieHelper.class);
    private final ClientService clientService = mock(ClientService.class);
    private static final AuthFrontend authFrontend = mock(AuthFrontend.class);
    private static final String TEST_FRONTEND_ERROR_URI = "test.orchestration.frontend.url/error";
    private static final String TEST_AUTH_BACKEND_BASE_URL = "https://test.auth.backend.url";
    private static final String TEST_EMAIL_ADDRESS = "test@test.com";
    private static final String PERSISTENT_SESSION_ID =
            "uDjIfGhoKwP8bFpRewlpd-AVrI4--1700750982787";
    private static final String SESSION_ID = "a-session-id";
    private static final Session session =
            new Session(SESSION_ID)
                    .setVerifiedMfaMethodType(MFAMethodType.EMAIL)
                    .setAuthenticated(false)
                    .setCurrentCredentialStrength(null);
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final ClientID CLIENT_ID = new ClientID();
    private static final String CLIENT_NAME = "client-name";
    private static final String TEST_INTERNAL_COMMON_SUBJECT_ID = "internal-common-subject-id";
    private static final Subject RP_PAIRWISE_ID = new Subject();
    private static final URI REDIRECT_URI = URI.create("https://test.rp.redirect.uri");
    private static final URI IPV_REDIRECT_URI = URI.create("https://test.ipv.redirect.uri");
    private static final State RP_STATE = new State();
    private static final Nonce RP_NONCE = new Nonce();
    private static final CredentialTrustLevel lowestCredentialTrustLevel =
            CredentialTrustLevel.LOW_LEVEL;
    private static final ClientSession clientSession =
            new ClientSession(
                    generateRPAuthRequestForClientSession().toParameters(),
                    null,
                    List.of(
                            VectorOfTrust.of(
                                    lowestCredentialTrustLevel, LevelOfConfidence.LOW_LEVEL)),
                    CLIENT_NAME);
    private static final String COOKIE_HEADER_NAME = "Cookie";
    private static final AuthorizationCode AUTH_CODE_ORCH_TO_AUTH = new AuthorizationCode();
    private static final AuthorizationCode AUTH_CODE_RP_TO_ORCH = new AuthorizationCode();
    private static final State STATE = new State();
    private static final TokenResponse SUCCESSFUL_TOKEN_RESPONSE =
            new AccessTokenResponse(new Tokens(new BearerAccessToken(), null));
    private static final TokenResponse UNSUCCESSFUL_TOKEN_RESPONSE = mock(TokenResponse.class);
    private static final String TEST_ERROR_MESSAGE = "test-error-message";
    private static final UserInfo USER_INFO = mock(UserInfo.class);
    private AuthenticationCallbackHandler handler;

    @BeforeAll
    static void init() {
        when(configurationService.getEnvironment()).thenReturn("test-env");
        when(authFrontend.errorURI()).thenReturn(URI.create(TEST_FRONTEND_ERROR_URI));
        when(configurationService.getAuthenticationBackendURI())
                .thenReturn(URI.create(TEST_AUTH_BACKEND_BASE_URL));
        when(configurationService.isAccountInterventionServiceCallEnabled()).thenReturn(false);
        when(configurationService.isAccountInterventionServiceActionEnabled()).thenReturn(false);
        when(configurationService.isDestroyOrchSessionOnSignOutEnabled()).thenReturn(true);
        when(accountInterventionService.getAccountIntervention(anyString(), any(), any()))
                .thenReturn(
                        new AccountIntervention(
                                new AccountInterventionState(false, false, false, false)));
        when(authorisationCodeService.generateAndSaveAuthorisationCode(
                        eq(CLIENT_SESSION_ID),
                        eq(TEST_EMAIL_ADDRESS),
                        eq(clientSession),
                        any(Long.class)))
                .thenReturn(AUTH_CODE_RP_TO_ORCH);
        when(cookieHelper.parseSessionCookie(anyMap())).thenCallRealMethod();
        when(UNSUCCESSFUL_TOKEN_RESPONSE.indicatesSuccess()).thenReturn(false);
        when(UNSUCCESSFUL_TOKEN_RESPONSE.toErrorResponse())
                .thenReturn(new TokenErrorResponse(new ErrorObject("1", TEST_ERROR_MESSAGE)));
        when(USER_INFO.getEmailAddress()).thenReturn(TEST_EMAIL_ADDRESS);
        when(USER_INFO.getSubject()).thenReturn(new Subject(TEST_INTERNAL_COMMON_SUBJECT_ID));
        when(USER_INFO.getClaim(AuthUserInfoClaims.RP_PAIRWISE_ID.getValue(), String.class))
                .thenReturn(RP_PAIRWISE_ID.getValue());
        when(USER_INFO.getStringClaim(AuthUserInfoClaims.RP_PAIRWISE_ID.getValue()))
                .thenReturn(RP_PAIRWISE_ID.getValue());
        when(USER_INFO.getPhoneNumber()).thenReturn("1234");
        when(USER_INFO.getClaim(
                        AuthUserInfoClaims.VERIFIED_MFA_METHOD_TYPE.getValue(), String.class))
                .thenReturn(MFAMethodType.AUTH_APP.getValue());
        when(USER_INFO.getBooleanClaim(AuthUserInfoClaims.UPLIFT_REQUIRED.getValue()))
                .thenReturn(false);
    }

    @BeforeEach
    void setUp() {
        reset(initiateIPVAuthorisationService);
        reset(logoutService);
        reset(authorizationService);
        session.setCurrentCredentialStrength(null);
        when(USER_INFO.getBooleanClaim("new_account")).thenReturn(true);
        when(USER_INFO.getStringClaim(AuthUserInfoClaims.CURRENT_CREDENTIAL_STRENGTH.getValue()))
                .thenReturn(null);
        when(logoutService.handleReauthenticationFailureLogout(any(), any(), any(), any()))
                .thenAnswer(
                        args -> {
                            var errorRedirectUri = (URI) args.getArgument(3);
                            return new APIGatewayProxyResponseEvent()
                                    .withStatusCode(302)
                                    .withHeaders(
                                            Map.of(
                                                    ResponseHeaders.LOCATION,
                                                    errorRedirectUri.toString()));
                        });
        handler =
                new AuthenticationCallbackHandler(
                        configurationService,
                        authorizationService,
                        tokenService,
                        sessionService,
                        orchSessionService,
                        clientSessionService,
                        auditService,
                        userInfoStorageService,
                        cookieHelper,
                        cloudwatchMetricsService,
                        authorisationCodeService,
                        clientService,
                        initiateIPVAuthorisationService,
                        accountInterventionService,
                        logoutService,
                        authFrontend);
    }

    @Test
    void shouldRedirectToRpRedirectUriWithCodeAndStateOnSuccessfulTokenResponse()
            throws UnsuccessfulCredentialResponseException {
        usingValidSession();
        usingValidClientSession();
        usingValidClient();

        var event = new APIGatewayProxyRequestEvent();
        setValidHeadersAndQueryParameters(event);

        when(tokenService.sendTokenRequest(any())).thenReturn(SUCCESSFUL_TOKEN_RESPONSE);

        when(tokenService.sendUserInfoDataRequest(any(HTTPRequest.class))).thenReturn(USER_INFO);

        var response = handler.handleRequest(event, null);

        assertThat(response, hasStatus(302));
        String redirectLocation = response.getHeaders().get("Location");
        assertThat(
                redirectLocation,
                equalTo(REDIRECT_URI + "?code=" + AUTH_CODE_RP_TO_ORCH + "&state=" + RP_STATE));
        verifyUserInfoRequest();

        assertSessionUpdatedAuthJourney();

        verify(cloudwatchMetricsService).incrementCounter(eq("AuthenticationCallback"), any());
        verify(cloudwatchMetricsService).incrementCounter(eq("SignIn"), any());
        verify(cloudwatchMetricsService)
                .incrementSignInByClient(
                        eq(OrchSessionItem.AccountState.NEW),
                        eq(CLIENT_ID.getValue()),
                        eq(CLIENT_NAME),
                        eq(false));

        verifyAuditEvents(
                List.of(
                        OrchestrationAuditableEvent.AUTH_CALLBACK_RESPONSE_RECEIVED,
                        OrchestrationAuditableEvent.AUTH_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        OrchestrationAuditableEvent.AUTH_SUCCESSFUL_USERINFO_RESPONSE_RECEIVED),
                auditService);

        verify(auditService)
                .submitAuditEvent(
                        eq(OidcAuditableEvent.AUTHENTICATION_COMPLETE),
                        eq(CLIENT_ID.getValue()),
                        eq(
                                TxmaAuditUser.user()
                                        .withSessionId(SESSION_ID)
                                        .withPersistentSessionId(PERSISTENT_SESSION_ID)
                                        .withGovukSigninJourneyId(CLIENT_SESSION_ID)
                                        .withIpAddress("123.123.123.123")
                                        .withUserId(TEST_INTERNAL_COMMON_SUBJECT_ID)
                                        .withEmail(TEST_EMAIL_ADDRESS)
                                        .withPhone("1234")),
                        eq(pair("new_account", true)),
                        eq(pair("test_user", false)),
                        eq(pair("credential_trust_level", "LOW_LEVEL")));
        verify(auditService)
                .submitAuditEvent(
                        eq(OidcAuditableEvent.AUTH_CODE_ISSUED),
                        eq(CLIENT_ID.getValue()),
                        eq(
                                TxmaAuditUser.user()
                                        .withSessionId(SESSION_ID)
                                        .withPersistentSessionId(PERSISTENT_SESSION_ID)
                                        .withGovukSigninJourneyId(CLIENT_SESSION_ID)
                                        .withIpAddress("123.123.123.123")
                                        .withUserId(TEST_INTERNAL_COMMON_SUBJECT_ID)
                                        .withEmail(TEST_EMAIL_ADDRESS)
                                        .withPhone("1234")),
                        eq(pair("internalSubjectId", AuditService.UNKNOWN)),
                        eq(pair("isNewAccount", true)),
                        eq(pair("rpPairwiseId", RP_PAIRWISE_ID.getValue())),
                        eq(pair("authCode", AUTH_CODE_RP_TO_ORCH.getValue())),
                        eq(pair("nonce", RP_NONCE.getValue())));
        assertOrchSessionUpdated();
        assertClientSessionUpdated();
    }

    @Test
    void shouldRedirectToFrontendErrorPageWhenSessionCookieNotFound() {
        var event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(Collections.emptyMap());
        event.setHeaders(Collections.emptyMap());

        var response = handler.handleRequest(event, null);

        assertThat(response, hasStatus(302));
        assertThat(response.getHeaders().get("Location"), equalTo(TEST_FRONTEND_ERROR_URI));

        verifyNoInteractions(
                tokenService, auditService, userInfoStorageService, cloudwatchMetricsService);
    }

    @Test
    void shouldRedirectToRpWithErrorWhenRequestIsInvalid()
            throws AuthenticationCallbackValidationException {
        usingValidSession();
        usingValidClientSession();

        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE_HEADER_NAME, buildCookieString()));
        doThrow(new AuthenticationCallbackValidationException())
                .when(authorizationService)
                .validateRequest(any(), any());

        var response = handler.handleRequest(event, null);

        assertThat(response, hasStatus(302));
        String locationHeaderRedirect = response.getHeaders().get("Location");
        assertThat(locationHeaderRedirect, containsString(REDIRECT_URI.toString()));
        assertThat(locationHeaderRedirect, containsString(OAuth2Error.SERVER_ERROR.getCode()));
        assertThat(locationHeaderRedirect, containsString("&state=" + RP_STATE));

        verifyAuditEvents(
                List.of(OrchestrationAuditableEvent.AUTH_UNSUCCESSFUL_CALLBACK_RESPONSE_RECEIVED),
                auditService);

        verifyNoInteractions(
                tokenService, userInfoStorageService, cloudwatchMetricsService, logoutService);
    }

    @Test
    void shouldLogoutAndRedirectToRpWithErrorWhenRequestIsInvalid()
            throws AuthenticationCallbackValidationException {
        usingValidSession();
        usingValidClientSession();

        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE_HEADER_NAME, buildCookieString()));
        doThrow(new AuthenticationCallbackValidationException(OIDCError.LOGIN_REQUIRED, true))
                .when(authorizationService)
                .validateRequest(any(), any());

        var response = handler.handleRequest(event, null);

        assertThat(response, hasStatus(302));
        String locationHeaderRedirect = response.getHeaders().get("Location");
        assertThat(locationHeaderRedirect, containsString(REDIRECT_URI.toString()));
        assertThat(locationHeaderRedirect, containsString(OIDCError.LOGIN_REQUIRED.getCode()));
        assertThat(locationHeaderRedirect, containsString("&state=" + RP_STATE));

        verifyAuditEvents(
                List.of(OrchestrationAuditableEvent.AUTH_UNSUCCESSFUL_CALLBACK_RESPONSE_RECEIVED),
                auditService);

        verify(logoutService, times(1))
                .handleReauthenticationFailureLogout(
                        eq(session), eq(event), eq(CLIENT_ID.toString()), any());

        verifyNoInteractions(tokenService, userInfoStorageService, cloudwatchMetricsService);
    }

    @Test
    void shouldRedirectToFrontendErrorPageIfTokenRequestIsUnsuccessful() {
        usingValidSession();
        usingValidClientSession();

        var event = new APIGatewayProxyRequestEvent();
        setValidHeadersAndQueryParameters(event);
        when(tokenService.sendTokenRequest(any())).thenReturn(UNSUCCESSFUL_TOKEN_RESPONSE);

        var response = handler.handleRequest(event, null);

        assertThat(response, hasStatus(302));
        assertThat(response.getHeaders().get("Location"), equalTo(TEST_FRONTEND_ERROR_URI));

        verifyAuditEvents(
                List.of(
                        OrchestrationAuditableEvent.AUTH_CALLBACK_RESPONSE_RECEIVED,
                        OrchestrationAuditableEvent.AUTH_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED),
                auditService);
        verifyNoInteractions(userInfoStorageService, cloudwatchMetricsService);
    }

    @Test
    void shouldRedirectToFrontendErrorPageIfUserInfoRequestIsUnsuccessful()
            throws UnsuccessfulCredentialResponseException {
        usingValidSession();
        usingValidClientSession();

        var event = new APIGatewayProxyRequestEvent();
        setValidHeadersAndQueryParameters(event);
        when(tokenService.sendTokenRequest(any())).thenReturn(SUCCESSFUL_TOKEN_RESPONSE);
        when(tokenService.sendUserInfoDataRequest(any(HTTPRequest.class)))
                .thenThrow(new UnsuccessfulCredentialResponseException(TEST_ERROR_MESSAGE));

        var response = handler.handleRequest(event, null);

        assertThat(response, hasStatus(302));
        assertThat(response.getHeaders().get("Location"), equalTo(TEST_FRONTEND_ERROR_URI));
        verifyUserInfoRequest();
        verifyAuditEvents(
                List.of(
                        OrchestrationAuditableEvent.AUTH_CALLBACK_RESPONSE_RECEIVED,
                        OrchestrationAuditableEvent.AUTH_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
                        OrchestrationAuditableEvent.AUTH_UNSUCCESSFUL_USERINFO_RESPONSE_RECEIVED),
                auditService);
        verifyNoInteractions(userInfoStorageService, cloudwatchMetricsService);
    }

    @Test
    void shouldUpdateOrchSessionUsingClaimsFromUserInfoResponse()
            throws UnsuccessfulCredentialResponseException {
        usingValidSession();
        usingValidClientSession();
        usingValidClient();
        var event = new APIGatewayProxyRequestEvent();
        setValidHeadersAndQueryParameters(event);
        when(tokenService.sendTokenRequest(any())).thenReturn(SUCCESSFUL_TOKEN_RESPONSE);
        when(tokenService.sendUserInfoDataRequest(any(HTTPRequest.class))).thenReturn(USER_INFO);

        handler.handleRequest(event, null);

        var orchSessionCaptor = ArgumentCaptor.forClass(OrchSessionItem.class);
        verify(orchSessionService, times(3)).updateSession(orchSessionCaptor.capture());
        assertThat(
                OrchSessionItem.AccountState.NEW,
                equalTo(orchSessionCaptor.getAllValues().get(0).getIsNewAccount()));
        assertThat(
                MFAMethodType.AUTH_APP.getValue(),
                equalTo(orchSessionCaptor.getAllValues().get(1).getVerifiedMfaMethodType()));
        assertEquals(
                TEST_INTERNAL_COMMON_SUBJECT_ID,
                orchSessionCaptor.getValue().getInternalCommonSubjectId());
    }

    @Test
    void shouldSetAccountStateToUnknownWhenNewAccountClaimIsNull()
            throws UnsuccessfulCredentialResponseException {
        when(USER_INFO.getBooleanClaim("new_account")).thenReturn(null);
        usingValidSession();
        usingValidClientSession();
        usingValidClient();
        var event = new APIGatewayProxyRequestEvent();
        setValidHeadersAndQueryParameters(event);
        when(tokenService.sendTokenRequest(any())).thenReturn(SUCCESSFUL_TOKEN_RESPONSE);
        when(tokenService.sendUserInfoDataRequest(any(HTTPRequest.class))).thenReturn(USER_INFO);

        handler.handleRequest(event, null);

        var sessionSaveCaptor = ArgumentCaptor.forClass(Session.class);
        var orchSessionCaptor = ArgumentCaptor.forClass(OrchSessionItem.class);
        verify(sessionService, times(2)).storeOrUpdateSession(sessionSaveCaptor.capture());
        verify(orchSessionService, times(3)).updateSession(orchSessionCaptor.capture());
        assertThat(
                Session.AccountState.UNKNOWN,
                equalTo(sessionSaveCaptor.getAllValues().get(0).isNewAccount()));
        assertThat(
                OrchSessionItem.AccountState.UNKNOWN,
                equalTo(orchSessionCaptor.getAllValues().get(0).getIsNewAccount()));
    }

    @Test
    void shouldAuditMediumCredentialTrustLevelOn2FARequest()
            throws UnsuccessfulCredentialResponseException {
        usingValidSession();
        var mediumRequestSession =
                new ClientSession(
                        generateRPAuthRequestForClientSession().toParameters(),
                        null,
                        List.of(
                                VectorOfTrust.of(
                                        CredentialTrustLevel.MEDIUM_LEVEL,
                                        LevelOfConfidence.LOW_LEVEL)),
                        CLIENT_NAME);

        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(mediumRequestSession));
        when(authorisationCodeService.generateAndSaveAuthorisationCode(
                        eq(CLIENT_SESSION_ID),
                        eq(TEST_EMAIL_ADDRESS),
                        eq(mediumRequestSession),
                        any(Long.class)))
                .thenReturn(AUTH_CODE_RP_TO_ORCH);
        usingValidClient();

        var event = new APIGatewayProxyRequestEvent();
        setValidHeadersAndQueryParameters(event);

        when(tokenService.sendTokenRequest(any())).thenReturn(SUCCESSFUL_TOKEN_RESPONSE);

        when(tokenService.sendUserInfoDataRequest(any(HTTPRequest.class))).thenReturn(USER_INFO);

        handler.handleRequest(event, null);

        verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.AUTHENTICATION_COMPLETE,
                        CLIENT_ID.getValue(),
                        TxmaAuditUser.user()
                                .withSessionId(SESSION_ID)
                                .withPersistentSessionId(PERSISTENT_SESSION_ID)
                                .withGovukSigninJourneyId(CLIENT_SESSION_ID)
                                .withIpAddress("123.123.123.123")
                                .withUserId(TEST_INTERNAL_COMMON_SUBJECT_ID)
                                .withEmail(TEST_EMAIL_ADDRESS)
                                .withPhone("1234"),
                        pair("new_account", true),
                        pair("test_user", false),
                        pair("credential_trust_level", "MEDIUM_LEVEL"));
    }

    @Test
    void shouldAuditMediumCredentialTrustLevelOn1FARequestWhenPreviously2FA()
            throws UnsuccessfulCredentialResponseException {
        Session mediumLevelSession =
                new Session(SESSION_ID)
                        .setVerifiedMfaMethodType(MFAMethodType.EMAIL)
                        .setCurrentCredentialStrength(CredentialTrustLevel.MEDIUM_LEVEL);
        when(sessionService.getSession(SESSION_ID)).thenReturn(Optional.of(mediumLevelSession));
        when(orchSessionService.getSession(SESSION_ID))
                .thenReturn(Optional.of(new OrchSessionItem(SESSION_ID)));
        usingValidClientSession();
        usingValidClient();

        var event = new APIGatewayProxyRequestEvent();
        setValidHeadersAndQueryParameters(event);

        when(tokenService.sendTokenRequest(any())).thenReturn(SUCCESSFUL_TOKEN_RESPONSE);

        when(tokenService.sendUserInfoDataRequest(any(HTTPRequest.class))).thenReturn(USER_INFO);

        handler.handleRequest(event, null);

        verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.AUTHENTICATION_COMPLETE,
                        CLIENT_ID.getValue(),
                        TxmaAuditUser.user()
                                .withSessionId(SESSION_ID)
                                .withPersistentSessionId(PERSISTENT_SESSION_ID)
                                .withGovukSigninJourneyId(CLIENT_SESSION_ID)
                                .withIpAddress("123.123.123.123")
                                .withUserId(TEST_INTERNAL_COMMON_SUBJECT_ID)
                                .withEmail(TEST_EMAIL_ADDRESS)
                                .withPhone("1234"),
                        pair("new_account", true),
                        pair("test_user", false),
                        pair("credential_trust_level", "MEDIUM_LEVEL"));
    }

    private static Stream<Arguments> currentCredentialStrengthParams() {
        return Stream.of(
                Arguments.of(
                        null, CredentialTrustLevel.MEDIUM_LEVEL, CredentialTrustLevel.MEDIUM_LEVEL),
                Arguments.of(
                        CredentialTrustLevel.LOW_LEVEL,
                        CredentialTrustLevel.MEDIUM_LEVEL,
                        CredentialTrustLevel.MEDIUM_LEVEL),
                Arguments.of(
                        CredentialTrustLevel.MEDIUM_LEVEL,
                        CredentialTrustLevel.MEDIUM_LEVEL,
                        CredentialTrustLevel.MEDIUM_LEVEL),
                Arguments.of(null, CredentialTrustLevel.LOW_LEVEL, CredentialTrustLevel.LOW_LEVEL),
                Arguments.of(
                        CredentialTrustLevel.LOW_LEVEL,
                        CredentialTrustLevel.LOW_LEVEL,
                        CredentialTrustLevel.LOW_LEVEL),
                Arguments.of(
                        CredentialTrustLevel.MEDIUM_LEVEL,
                        CredentialTrustLevel.LOW_LEVEL,
                        CredentialTrustLevel.MEDIUM_LEVEL));
    }

    @ParameterizedTest
    @MethodSource("currentCredentialStrengthParams")
    void shouldSetTheCurrentCredentialStrengthToTheLowestCredentialTrustLevel(
            CredentialTrustLevel userInfoCurrentCredentialStrengthResponse,
            CredentialTrustLevel credentialTrustLevel,
            CredentialTrustLevel correctCurrentCredentialStrengthSet)
            throws UnsuccessfulCredentialResponseException {
        usingValidSession();
        returnCurrentCredentialStrengthValue(userInfoCurrentCredentialStrengthResponse);
        clientSessionWithCredentialTrustValue(credentialTrustLevel);
        usingValidClient();
        var event = new APIGatewayProxyRequestEvent();
        setValidHeadersAndQueryParameters(event);
        when(tokenService.sendTokenRequest(any())).thenReturn(SUCCESSFUL_TOKEN_RESPONSE);
        when(tokenService.sendUserInfoDataRequest(any(HTTPRequest.class))).thenReturn(USER_INFO);

        handler.handleRequest(event, null);

        assertCurrentCredentialSetCorrectly(correctCurrentCredentialStrengthSet);
    }

    @Nested
    class AuthTime {

        private static Stream<Arguments> authenticatedAndUpliftParams() {
            return Stream.of(
                    Arguments.of(false, false, true),
                    Arguments.of(true, true, true),
                    Arguments.of(false, true, true),
                    Arguments.of(true, false, false),
                    Arguments.of(true, null, false));
        }

        @ParameterizedTest
        @MethodSource("authenticatedAndUpliftParams")
        void shouldSetOrNotSetAuthTimeDependingOnValuesOfAuthenticatedAndUpliftRequired(
                Boolean authenticated, Boolean upliftRequired, boolean authTimeSet)
                throws UnsuccessfulCredentialResponseException {
            when(sessionService.getSession(SESSION_ID)).thenReturn(Optional.of(session));
            when(orchSessionService.getSession(SESSION_ID))
                    .thenReturn(
                            Optional.of(
                                    new OrchSessionItem(SESSION_ID)
                                            .withAuthenticated(authenticated)));
            usingValidClientSession();
            usingValidClient();
            when(tokenService.sendTokenRequest(any())).thenReturn(SUCCESSFUL_TOKEN_RESPONSE);
            when(tokenService.sendUserInfoDataRequest(any(HTTPRequest.class)))
                    .thenReturn(USER_INFO);
            when(USER_INFO.getBooleanClaim(AuthUserInfoClaims.UPLIFT_REQUIRED.getValue()))
                    .thenReturn(upliftRequired);

            var event = new APIGatewayProxyRequestEvent();
            setValidHeadersAndQueryParameters(event);
            handler.handleRequest(event, null);

            var captor = ArgumentCaptor.forClass(OrchSessionItem.class);
            verify(orchSessionService, times(2)).updateSession(captor.capture());

            if (authTimeSet) {
                assertNotEquals(null, captor.getAllValues().get(0).getAuthTime());
            } else {
                assertNull(captor.getAllValues().get(0).getAuthTime());
            }
        }
    }

    @Nested
    class AccountInterventions {
        private static MockedStatic<IdentityHelper> mockedIdentityHelper;

        @BeforeEach
        void setup() throws UnsuccessfulCredentialResponseException {
            mockedIdentityHelper = mockStatic(IdentityHelper.class);
            when(tokenService.sendTokenRequest(any())).thenReturn(SUCCESSFUL_TOKEN_RESPONSE);
            when(tokenService.sendUserInfoDataRequest(any(HTTPRequest.class)))
                    .thenReturn(USER_INFO);
            when(configurationService.isAccountInterventionServiceCallEnabled()).thenReturn(true);
            when(configurationService.isAccountInterventionServiceActionEnabled()).thenReturn(true);
            usingValidSession();
            usingValidClientSession();
            usingValidClient();
        }

        @AfterEach
        void afterEach() {
            mockedIdentityHelper.close();
        }

        @Nested
        class AuthOnlyJourney {
            @BeforeEach
            void setup() {
                when(IdentityHelper.identityRequired(anyMap(), anyBoolean(), anyBoolean()))
                        .thenReturn(false);
            }

            @Test
            void shouldRedirectToRpWhenAccountStatusIsNoIntervention() {
                setUpIntervention(false, false, false, false);

                var event = new APIGatewayProxyRequestEvent();
                setValidHeadersAndQueryParameters(event);

                var response = handler.handleRequest(event, null);

                assertThat(response, hasStatus(302));
                String redirectLocation = response.getHeaders().get("Location");
                assertThat(
                        redirectLocation,
                        equalTo(
                                REDIRECT_URI
                                        + "?code="
                                        + AUTH_CODE_RP_TO_ORCH
                                        + "&state="
                                        + RP_STATE));
                assertOrchSessionUpdated();
            }

            @Test
            void shouldLogoutWhenAccountStatusIsBlocked() {
                AccountIntervention intervention = setUpIntervention(true, false, false, false);

                var event = new APIGatewayProxyRequestEvent();
                setValidHeadersAndQueryParameters(event);

                handler.handleRequest(event, null);

                verify(logoutService)
                        .handleAccountInterventionLogout(
                                session, event, CLIENT_ID.toString(), intervention);
            }

            @Test
            void shouldLogoutWhenAccountStatusIsSuspendedNoAction() {
                AccountIntervention intervention = setUpIntervention(false, true, false, false);

                var event = new APIGatewayProxyRequestEvent();
                setValidHeadersAndQueryParameters(event);

                handler.handleRequest(event, null);

                verify(logoutService)
                        .handleAccountInterventionLogout(
                                session, event, CLIENT_ID.toString(), intervention);
            }

            @Test
            void shouldLogoutWhenAccountStatusIsSuspendedResetPassword() {
                AccountIntervention intervention = setUpIntervention(false, true, false, true);

                var event = new APIGatewayProxyRequestEvent();
                setValidHeadersAndQueryParameters(event);

                handler.handleRequest(event, null);

                verify(logoutService)
                        .handleAccountInterventionLogout(
                                session, event, CLIENT_ID.toString(), intervention);
            }

            @Test
            void shouldRedirectToRpWhenAccountStatusIsSuspendedReproveIdentity() {
                setUpIntervention(false, true, true, false);

                var event = new APIGatewayProxyRequestEvent();
                setValidHeadersAndQueryParameters(event);

                var response = handler.handleRequest(event, null);

                assertThat(response, hasStatus(302));
                String redirectLocation = response.getHeaders().get("Location");
                assertThat(
                        redirectLocation,
                        equalTo(
                                REDIRECT_URI
                                        + "?code="
                                        + AUTH_CODE_RP_TO_ORCH
                                        + "&state="
                                        + RP_STATE));
            }

            @Test
            void shouldLogoutWhenAccountStatusIsSuspendedResetPasswordReproveIdentity() {
                AccountIntervention intervention = setUpIntervention(false, true, true, true);

                var event = new APIGatewayProxyRequestEvent();
                setValidHeadersAndQueryParameters(event);

                handler.handleRequest(event, null);

                verify(logoutService)
                        .handleAccountInterventionLogout(
                                session, event, CLIENT_ID.getValue(), intervention);
            }
        }

        @Nested
        class IdentityJourney {

            @BeforeEach
            void setup() {
                when(IdentityHelper.identityRequired(anyMap(), anyBoolean(), anyBoolean()))
                        .thenReturn(true);
            }

            @Test
            void shouldRedirectToIPVWhenThereIsNoIntervention() {
                boolean reproveIdentity = false;
                setUpIntervention(false, false, reproveIdentity, false);

                var event = new APIGatewayProxyRequestEvent();
                setValidHeadersAndQueryParameters(event);

                handler.handleRequest(event, null);

                verify(initiateIPVAuthorisationService)
                        .sendRequestToIPV(
                                any(),
                                any(),
                                any(),
                                any(),
                                any(),
                                any(),
                                any(),
                                any(),
                                eq(reproveIdentity),
                                any());
                verifyNoInteractions(logoutService);
                verify(sessionService).storeOrUpdateSession(argThat(Session::isAuthenticated));
                verify(orchSessionService, times(2))
                        .updateSession(argThat(OrchSessionItem::getAuthenticated));
            }

            @Test
            void shouldLogoutWhenAccountStatusIsBlocked() {
                AccountIntervention intervention = setUpIntervention(true, false, false, false);

                var event = new APIGatewayProxyRequestEvent();
                setValidHeadersAndQueryParameters(event);

                handler.handleRequest(event, null);

                verify(logoutService)
                        .handleAccountInterventionLogout(any(), any(), any(), eq(intervention));
                verifyNoInteractions(initiateIPVAuthorisationService);
                verify(sessionService).storeOrUpdateSession(argThat(Session::isAuthenticated));
                verify(orchSessionService, times(2))
                        .updateSession(argThat(OrchSessionItem::getAuthenticated));
            }

            @Test
            void shouldRedirectToIPVWhenAccountStatusIsSuspendedNoAction() {
                boolean reproveIdentity = false;
                setUpIntervention(false, true, reproveIdentity, false);

                var event = new APIGatewayProxyRequestEvent();
                setValidHeadersAndQueryParameters(event);

                handler.handleRequest(event, null);

                verify(initiateIPVAuthorisationService)
                        .sendRequestToIPV(
                                any(),
                                any(),
                                any(),
                                any(),
                                any(),
                                any(),
                                any(),
                                any(),
                                eq(reproveIdentity),
                                any());
                verifyNoInteractions(logoutService);
                verify(sessionService).storeOrUpdateSession(argThat(Session::isAuthenticated));
                verify(orchSessionService, times(2))
                        .updateSession(argThat(OrchSessionItem::getAuthenticated));
            }

            @Test
            void shouldLogoutWhenAccountStatusIsSuspendedResetPassword() {
                AccountIntervention intervention = setUpIntervention(false, true, false, true);

                var event = new APIGatewayProxyRequestEvent();
                setValidHeadersAndQueryParameters(event);

                handler.handleRequest(event, null);

                verify(logoutService)
                        .handleAccountInterventionLogout(any(), any(), any(), eq(intervention));
                verifyNoInteractions(initiateIPVAuthorisationService);
                verify(sessionService).storeOrUpdateSession(argThat(Session::isAuthenticated));
            }

            @Test
            void shouldRedirectToIPVWhenAccountStatusIsSuspendedReproveIdentity() {
                boolean reproveIdentity = true;
                setUpIntervention(false, true, reproveIdentity, false);

                var event = new APIGatewayProxyRequestEvent();
                setValidHeadersAndQueryParameters(event);

                handler.handleRequest(event, null);

                verify(initiateIPVAuthorisationService)
                        .sendRequestToIPV(
                                any(),
                                any(),
                                any(),
                                any(),
                                any(),
                                any(),
                                any(),
                                any(),
                                eq(reproveIdentity),
                                any());
                verifyNoInteractions(logoutService);
                verify(sessionService).storeOrUpdateSession(argThat(Session::isAuthenticated));
                verify(orchSessionService, times(2))
                        .updateSession(argThat(OrchSessionItem::getAuthenticated));
            }

            @Test
            void shouldLogoutWhenAccountStatusIsSuspendedResetPasswordAndReproveIdentity() {
                AccountIntervention intervention = setUpIntervention(false, true, true, true);

                var event = new APIGatewayProxyRequestEvent();
                setValidHeadersAndQueryParameters(event);

                handler.handleRequest(event, null);

                verify(logoutService)
                        .handleAccountInterventionLogout(any(), any(), any(), eq(intervention));
                verifyNoInteractions(initiateIPVAuthorisationService);
            }
        }
    }

    @Nested
    class MaxAgeSessionHandling {
        private static final String PREVIOUS_SESSION_ID = "9a3f2708-2bf1-40d8-9c25-7b94145ef535";
        private static final String INTERNAL_COMMON_SUBJECT_ID =
                "urn:fdc:gov:245469fb-7b5a-495c-84ec-c2b5b65c2fbd";
        private static final String DIFFERENT_INTERNAL_COMMON_SUBJECT_ID =
                "urn:fdc:gov:cebb94a1-3ee7-44ed-963b-f3befee65487";
        private static final List<String> PREVIOUS_CLIENT_SESSIONS =
                List.of(
                        "623f860d-1bce-43ea-8f82-446fc894160b",
                        "3eee3869-abf1-41c1-bdb5-c25f68d0a54d",
                        "aef54391-95d8-4d3b-ac30-cbe1e3e2f0d4");

        @BeforeEach
        void setup() {
            usingValidClientSession();
            usingValidClient();
            when(configurationService.supportMaxAgeEnabled()).thenReturn(true);
        }

        @Test
        void itCopiesThePreviousClientSessionsToTheCurrentSessionIfInternalCommonSubjectIdsMatch()
                throws UnsuccessfulCredentialResponseException {
            var orchSession = withMaxAgeOrchSession(INTERNAL_COMMON_SUBJECT_ID);
            var sharedSession = withMaxAgeSharedSession();
            withPreviousOrchSessionDueToMaxAge();
            withPreviousSharedSessionDueToMaxAge();

            when(tokenService.sendTokenRequest(any())).thenReturn(SUCCESSFUL_TOKEN_RESPONSE);
            when(tokenService.sendUserInfoDataRequest(any(HTTPRequest.class)))
                    .thenReturn(USER_INFO);
            when(USER_INFO.getSubject()).thenReturn(new Subject(INTERNAL_COMMON_SUBJECT_ID));

            var event = new APIGatewayProxyRequestEvent();
            setValidHeadersAndQueryParameters(event);
            var response = handler.handleRequest(event, null);

            assertThat(response, hasStatus(302));
            String redirectLocation = response.getHeaders().get("Location");
            assertThat(
                    redirectLocation,
                    equalTo(REDIRECT_URI + "?code=" + AUTH_CODE_RP_TO_ORCH + "&state=" + RP_STATE));

            assertEquals(PREVIOUS_CLIENT_SESSIONS, sharedSession.getClientSessions());
            assertNull(orchSession.getPreviousSessionId());
            verify(orchSessionService).getSession(PREVIOUS_SESSION_ID);
            verify(sessionService).getSession(PREVIOUS_SESSION_ID);
            verify(orchSessionService, times(3))
                    .updateSession(argThat(s -> s.getPreviousSessionId() == null));
            verify(sessionService, times(2))
                    .storeOrUpdateSession(
                            argThat(s -> s.getClientSessions().equals(PREVIOUS_CLIENT_SESSIONS)));
        }

        @Test
        void itDoesNotAssignClientSessionsIfItCannotFindThePreviousOrchSession()
                throws UnsuccessfulCredentialResponseException {
            var orchSession = withMaxAgeOrchSession(INTERNAL_COMMON_SUBJECT_ID);
            var sharedSession = withMaxAgeSharedSession();
            withNoPreviousOrchSession();
            withPreviousSharedSessionDueToMaxAge();

            when(tokenService.sendTokenRequest(any())).thenReturn(SUCCESSFUL_TOKEN_RESPONSE);
            when(tokenService.sendUserInfoDataRequest(any(HTTPRequest.class)))
                    .thenReturn(USER_INFO);
            when(USER_INFO.getSubject()).thenReturn(new Subject(INTERNAL_COMMON_SUBJECT_ID));

            var event = new APIGatewayProxyRequestEvent();
            setValidHeadersAndQueryParameters(event);
            var response = handler.handleRequest(event, null);

            assertThat(response, hasStatus(302));
            String redirectLocation = response.getHeaders().get("Location");
            assertThat(
                    redirectLocation,
                    equalTo(REDIRECT_URI + "?code=" + AUTH_CODE_RP_TO_ORCH + "&state=" + RP_STATE));

            assertEquals(List.of(), sharedSession.getClientSessions());
            assertNull(orchSession.getPreviousSessionId());
            verify(orchSessionService).getSession(PREVIOUS_SESSION_ID);
            verify(sessionService).getSession(PREVIOUS_SESSION_ID);
            verify(orchSessionService, times(3))
                    .updateSession(argThat(s -> s.getPreviousSessionId() == null));
            verify(sessionService, times(2))
                    .storeOrUpdateSession(argThat(s -> s.getClientSessions().equals(List.of())));
        }

        @Test
        void itDoesNotAssignClientSessionsIfItCannotFindThePreviousSharedSession()
                throws UnsuccessfulCredentialResponseException {
            var orchSession = withMaxAgeOrchSession(INTERNAL_COMMON_SUBJECT_ID);
            var sharedSession = withMaxAgeSharedSession();
            withPreviousOrchSessionDueToMaxAge();
            withNoPreviousSharedSession();

            when(tokenService.sendTokenRequest(any())).thenReturn(SUCCESSFUL_TOKEN_RESPONSE);
            when(tokenService.sendUserInfoDataRequest(any(HTTPRequest.class)))
                    .thenReturn(USER_INFO);
            when(USER_INFO.getSubject()).thenReturn(new Subject(INTERNAL_COMMON_SUBJECT_ID));

            var event = new APIGatewayProxyRequestEvent();
            setValidHeadersAndQueryParameters(event);
            var response = handler.handleRequest(event, null);

            assertThat(response, hasStatus(302));
            String redirectLocation = response.getHeaders().get("Location");
            assertThat(
                    redirectLocation,
                    equalTo(REDIRECT_URI + "?code=" + AUTH_CODE_RP_TO_ORCH + "&state=" + RP_STATE));

            assertEquals(List.of(), sharedSession.getClientSessions());
            assertNull(orchSession.getPreviousSessionId());
            verify(orchSessionService).getSession(PREVIOUS_SESSION_ID);
            verify(sessionService).getSession(PREVIOUS_SESSION_ID);
            verify(orchSessionService, times(3))
                    .updateSession(argThat(s -> s.getPreviousSessionId() == null));
            verify(sessionService, times(2))
                    .storeOrUpdateSession(argThat(s -> s.getClientSessions().equals(List.of())));
        }

        @Test
        void
                itSendsBackChannelLogoutNotificationForThePreviousSessionIfTheInternalCommonSubjectIdsDoNotMatch()
                        throws UnsuccessfulCredentialResponseException {
            var orchSession = withMaxAgeOrchSession(INTERNAL_COMMON_SUBJECT_ID);
            var sharedSession = withMaxAgeSharedSession();
            var previousOrchSession = withPreviousOrchSessionDueToMaxAge();
            var previousSharedSession = withPreviousSharedSessionDueToMaxAge();

            when(tokenService.sendTokenRequest(any())).thenReturn(SUCCESSFUL_TOKEN_RESPONSE);
            when(tokenService.sendUserInfoDataRequest(any(HTTPRequest.class)))
                    .thenReturn(USER_INFO);
            when(USER_INFO.getSubject())
                    .thenReturn(new Subject(DIFFERENT_INTERNAL_COMMON_SUBJECT_ID));

            var event = new APIGatewayProxyRequestEvent();
            setValidHeadersAndQueryParameters(event);
            var response = handler.handleRequest(event, null);

            assertThat(response, hasStatus(302));
            String redirectLocation = response.getHeaders().get("Location");
            assertThat(
                    redirectLocation,
                    equalTo(REDIRECT_URI + "?code=" + AUTH_CODE_RP_TO_ORCH + "&state=" + RP_STATE));

            assertEquals(List.of(), sharedSession.getClientSessions());
            assertNull(orchSession.getPreviousSessionId());
            verify(orchSessionService).getSession(PREVIOUS_SESSION_ID);
            verify(sessionService).getSession(PREVIOUS_SESSION_ID);
            verify(orchSessionService, times(3))
                    .updateSession(argThat(s -> s.getPreviousSessionId() == null));
            verify(sessionService, times(2))
                    .storeOrUpdateSession(argThat(s -> s.getClientSessions().equals(List.of())));

            verify(logoutService, times(1))
                    .handleMaxAgeLogout(
                            eq(previousSharedSession),
                            eq(previousOrchSession),
                            any(TxmaAuditUser.class));
        }

        private OrchSessionItem withPreviousOrchSessionDueToMaxAge() {
            var previousOrchSession =
                    new OrchSessionItem(PREVIOUS_SESSION_ID)
                            .withInternalCommonSubjectId(INTERNAL_COMMON_SUBJECT_ID);
            when(orchSessionService.getSession(PREVIOUS_SESSION_ID))
                    .thenReturn(Optional.of(previousOrchSession));
            return previousOrchSession;
        }

        private Session withPreviousSharedSessionDueToMaxAge() {
            var previousSharedSession = new Session(PREVIOUS_SESSION_ID);
            PREVIOUS_CLIENT_SESSIONS.forEach(previousSharedSession::addClientSession);
            when(sessionService.getSession(PREVIOUS_SESSION_ID))
                    .thenReturn(Optional.of(previousSharedSession));
            return previousSharedSession;
        }

        private void withNoPreviousSharedSession() {
            when(sessionService.getSession(PREVIOUS_SESSION_ID)).thenReturn(Optional.empty());
        }

        private void withNoPreviousOrchSession() {
            when(orchSessionService.getSession(PREVIOUS_SESSION_ID)).thenReturn(Optional.empty());
        }

        private OrchSessionItem withMaxAgeOrchSession(String internalCommonSubjectId) {
            var orchSession =
                    new OrchSessionItem(SESSION_ID)
                            .withPreviousSessionId(PREVIOUS_SESSION_ID)
                            .withInternalCommonSubjectId(internalCommonSubjectId);
            when(orchSessionService.getSession(SESSION_ID)).thenReturn(Optional.of(orchSession));
            return orchSession;
        }

        private Session withMaxAgeSharedSession() {
            var session = new Session(SESSION_ID);
            when(sessionService.getSession(SESSION_ID)).thenReturn(Optional.of(session));
            return session;
        }
    }

    private AccountIntervention setUpIntervention(
            boolean blocked, boolean suspended, boolean reproveIdentity, boolean resetPassword) {
        AccountIntervention intervention =
                new AccountIntervention(
                        new AccountInterventionState(
                                blocked, suspended, reproveIdentity, resetPassword));
        when(accountInterventionService.getAccountIntervention(anyString(), any(), any()))
                .thenReturn(intervention);
        return intervention;
    }

    private APIGatewayProxyResponseEvent createIPVApiResponse() {

        return generateApiGatewayProxyResponse(
                302, "", Map.of(ResponseHeaders.LOCATION, IPV_REDIRECT_URI.toString()), null);
    }

    private static void setValidHeadersAndQueryParameters(APIGatewayProxyRequestEvent event) {
        event.setHeaders(Map.of(COOKIE_HEADER_NAME, buildCookieString()));
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE_ORCH_TO_AUTH.getValue());
        responseHeaders.put("state", STATE.getValue());
        event.setQueryStringParameters(responseHeaders);
    }

    private void usingValidSession() {
        when(sessionService.getSession(SESSION_ID)).thenReturn(Optional.of(session));
        when(orchSessionService.getSession(SESSION_ID))
                .thenReturn(
                        Optional.of(
                                new OrchSessionItem(SESSION_ID)
                                        .withAuthenticated(false)
                                        .withCurrentCredentialStrength(null)));
    }

    private void usingValidClientSession() {
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(clientSession));
    }

    private void usingValidClient() {
        when(clientService.getClient(CLIENT_ID.toString()))
                .thenReturn(Optional.of(createClientRegistry()));
    }

    private ClientRegistry createClientRegistry() {
        return new ClientRegistry()
                .withClientName(CLIENT_NAME)
                .withClientID(CLIENT_ID.toString())
                .withPublicKey("public-key")
                .withSubjectType("Public")
                .withRedirectUrls(singletonList("http://localhost/redirect"))
                .withContacts(singletonList("contant-name"))
                .withPostLogoutRedirectUrls(singletonList("localhost/logout"))
                .withClientType(ClientType.WEB.getValue())
                .withClaims(List.of("claim"));
    }

    private static AuthenticationRequest generateRPAuthRequestForClientSession() {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        scope.add("phone");
        scope.add("email");
        return new AuthenticationRequest.Builder(responseType, scope, CLIENT_ID, REDIRECT_URI)
                .state(RP_STATE)
                .nonce(RP_NONCE)
                .build();
    }

    private static String buildCookieString() {
        return format(
                        "%s=%s.%s; Max-Age=%d; %s",
                        "gs", SESSION_ID, CLIENT_SESSION_ID, 3600, "Secure; HttpOnly;")
                + format(
                        "%s=%s; Max-Age=%d; %s",
                        "di-persistent-session-id",
                        PERSISTENT_SESSION_ID,
                        3600,
                        "Secure; HttpOnly;");
    }

    private static void verifyAuditEvents(
            List<AuditableEvent> auditEvents, AuditService auditService) {
        for (AuditableEvent event : auditEvents) {
            verify(auditService)
                    .submitAuditEvent(
                            eq(event),
                            eq(CLIENT_ID.getValue()),
                            eq(
                                    TxmaAuditUser.user()
                                            .withSessionId(SESSION_ID)
                                            .withPersistentSessionId(PERSISTENT_SESSION_ID)
                                            .withGovukSigninJourneyId(CLIENT_SESSION_ID)));
        }
    }

    private void verifyUserInfoRequest() throws UnsuccessfulCredentialResponseException {
        HTTPRequest expectedUserInfoRequest =
                new HTTPRequest(GET, buildURI(TEST_AUTH_BACKEND_BASE_URL, "userinfo"));
        expectedUserInfoRequest.setHeader(SESSION_ID_HEADER, SESSION_ID);
        expectedUserInfoRequest.setAuthorization(
                (SUCCESSFUL_TOKEN_RESPONSE
                        .toSuccessResponse()
                        .getTokens()
                        .getAccessToken()
                        .toAuthorizationHeader()));

        var userInfoRequest = ArgumentCaptor.forClass(HTTPRequest.class);
        verify(tokenService).sendUserInfoDataRequest(userInfoRequest.capture());
        assertEquals(expectedUserInfoRequest.getURI(), userInfoRequest.getValue().getURI());
        assertEquals(
                expectedUserInfoRequest.getHeaderMap(), userInfoRequest.getValue().getHeaderMap());
    }

    private void assertSessionUpdatedAuthJourney() {
        var sessionSaveCaptor = ArgumentCaptor.forClass(Session.class);
        verify(sessionService, times(2)).storeOrUpdateSession(sessionSaveCaptor.capture());
        assertThat(
                sessionSaveCaptor.getAllValues().get(0).getCurrentCredentialStrength(),
                equalTo(lowestCredentialTrustLevel));
        assertThat(
                Session.AccountState.NEW,
                equalTo(sessionSaveCaptor.getAllValues().get(0).isNewAccount()));
        assertTrue(sessionSaveCaptor.getAllValues().get(0).isAuthenticated());
    }

    private void assertOrchSessionUpdated() {
        var orchSessionCaptor = ArgumentCaptor.forClass(OrchSessionItem.class);
        verify(orchSessionService, times(3)).updateSession(orchSessionCaptor.capture());
        assertTrue(orchSessionCaptor.getAllValues().get(0).getAuthenticated());
        assertThat(
                orchSessionCaptor.getAllValues().get(0).getCurrentCredentialStrength(),
                equalTo(lowestCredentialTrustLevel));
    }

    private void assertClientSessionUpdated() {
        var clientSessionCaptor = ArgumentCaptor.forClass(ClientSession.class);
        verify(clientSessionService, times(1))
                .updateStoredClientSession(any(), clientSessionCaptor.capture());
        assertEquals(RP_PAIRWISE_ID.getValue(), clientSessionCaptor.getValue().getRpPairwiseId());
    }

    private void clientSessionWithCredentialTrustValue(CredentialTrustLevel credentialTrustLevel) {
        ClientSession clientSessionWithCredentialTrustLevel =
                createClientSession(credentialTrustLevel);
        when(authorisationCodeService.generateAndSaveAuthorisationCode(
                        eq(CLIENT_SESSION_ID),
                        eq(TEST_EMAIL_ADDRESS),
                        eq(clientSessionWithCredentialTrustLevel),
                        any(Long.class)))
                .thenReturn(AUTH_CODE_RP_TO_ORCH);
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(clientSessionWithCredentialTrustLevel));
    }

    private ClientSession createClientSession(CredentialTrustLevel credentialTrustLevel) {
        return new ClientSession(
                generateRPAuthRequestForClientSession().toParameters(),
                null,
                List.of(VectorOfTrust.of(credentialTrustLevel, LevelOfConfidence.LOW_LEVEL)),
                CLIENT_NAME);
    }

    private void returnCurrentCredentialStrengthValue(CredentialTrustLevel credentialTrustLevel) {
        when(USER_INFO.getStringClaim(AuthUserInfoClaims.CURRENT_CREDENTIAL_STRENGTH.getValue()))
                .thenReturn(Objects.toString(credentialTrustLevel, null));
    }

    private void assertCurrentCredentialSetCorrectly(
            CredentialTrustLevel currentCredentialStrength) {
        var orchSessionCaptor = ArgumentCaptor.forClass(OrchSessionItem.class);

        verify(orchSessionService, times(3)).updateSession(orchSessionCaptor.capture());
        assertThat(
                orchSessionCaptor.getAllValues().get(1).getCurrentCredentialStrength(),
                equalTo(currentCredentialStrength));
    }
}
