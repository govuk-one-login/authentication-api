package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCError;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
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
import uk.gov.di.orchestration.shared.entity.AccountIntervention;
import uk.gov.di.orchestration.shared.entity.AccountInterventionState;
import uk.gov.di.orchestration.shared.entity.AuthUserInfoClaims;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.DestroySessionsRequest;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.MFAMethodType;
import uk.gov.di.orchestration.shared.entity.NoSessionEntity;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.NoSessionException;
import uk.gov.di.orchestration.shared.exceptions.OrchAuthCodeException;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.services.AccountInterventionService;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.AuthenticationUserInfoStorageService;
import uk.gov.di.orchestration.shared.services.ClientService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.LogoutService;
import uk.gov.di.orchestration.shared.services.NoSessionOrchestrationService;
import uk.gov.di.orchestration.shared.services.OrchAuthCodeService;
import uk.gov.di.orchestration.shared.services.OrchClientSessionService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static com.nimbusds.oauth2.sdk.http.HTTPRequest.Method.GET;
import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
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
    private final OrchSessionService orchSessionService = mock(OrchSessionService.class);
    private final OrchClientSessionService orchClientSessionService =
            mock(OrchClientSessionService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final AuthenticationUserInfoStorageService userInfoStorageService =
            mock(AuthenticationUserInfoStorageService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private static final OrchAuthCodeService orchAuthCodeService = mock(OrchAuthCodeService.class);
    private static final InitiateIPVAuthorisationService initiateIPVAuthorisationService =
            mock(InitiateIPVAuthorisationService.class);
    private static final AccountInterventionService accountInterventionService =
            mock(AccountInterventionService.class);
    private static final NoSessionOrchestrationService noSessionOrchestrationService =
            mock(NoSessionOrchestrationService.class);
    private static final LogoutService logoutService = mock(LogoutService.class);
    private final ClientService clientService = mock(ClientService.class);
    private static final AuthFrontend authFrontend = mock(AuthFrontend.class);
    private static final String TEST_FRONTEND_ERROR_URI = "test.orchestration.frontend.url/error";
    private static final String TEST_AUTH_BACKEND_BASE_URL = "https://test.auth.backend.url";
    private static final String TEST_EMAIL_ADDRESS = "test@test.com";
    private static final String PERSISTENT_SESSION_ID =
            "uDjIfGhoKwP8bFpRewlpd-AVrI4--1700750982787";
    private static final String SESSION_ID = "a-session-id";

    public static final OrchSessionItem orchSession =
            new OrchSessionItem(SESSION_ID).withAuthenticated(false);
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final ClientID CLIENT_ID = new ClientID();
    private static final String CLIENT_NAME = "client-name";
    private static final String TEST_INTERNAL_COMMON_SUBJECT_ID = "internal-common-subject-id";
    private static final Subject RP_PAIRWISE_ID = new Subject();
    private static final Subject PUBLIC_SUBJECT_ID = new Subject();
    private static final URI REDIRECT_URI = URI.create("https://test.rp.redirect.uri");
    private static final URI IPV_REDIRECT_URI = URI.create("https://test.ipv.redirect.uri");
    private static final State RP_STATE = new State();
    private static final Nonce RP_NONCE = new Nonce();
    private static final CredentialTrustLevel lowestCredentialTrustLevel =
            CredentialTrustLevel.LOW_LEVEL;
    private static final OrchClientSessionItem orchClientSession =
            new OrchClientSessionItem(
                    CLIENT_SESSION_ID,
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
    private static final Context CONTEXT = mock(Context.class);
    private AuthenticationCallbackHandler handler;

    @BeforeAll
    static void init() {
        when(configurationService.getEnvironment()).thenReturn("test-env");
        when(authFrontend.errorURI()).thenReturn(URI.create(TEST_FRONTEND_ERROR_URI));
        when(configurationService.getAuthenticationBackendURI())
                .thenReturn(URI.create(TEST_AUTH_BACKEND_BASE_URL));
        when(configurationService.isAccountInterventionServiceCallEnabled()).thenReturn(false);
        when(configurationService.isAccountInterventionServiceActionEnabled()).thenReturn(false);
        when(accountInterventionService.getAccountIntervention(anyString(), any(), any()))
                .thenReturn(
                        new AccountIntervention(
                                new AccountInterventionState(false, false, false, false)));

        when(UNSUCCESSFUL_TOKEN_RESPONSE.indicatesSuccess()).thenReturn(false);
        when(UNSUCCESSFUL_TOKEN_RESPONSE.toErrorResponse())
                .thenReturn(new TokenErrorResponse(new ErrorObject("1", TEST_ERROR_MESSAGE)));
        when(USER_INFO.getEmailAddress()).thenReturn(TEST_EMAIL_ADDRESS);
        when(USER_INFO.getSubject()).thenReturn(new Subject(TEST_INTERNAL_COMMON_SUBJECT_ID));
        when(USER_INFO.getClaim(AuthUserInfoClaims.RP_PAIRWISE_ID.getValue(), String.class))
                .thenReturn(RP_PAIRWISE_ID.getValue());
        when(USER_INFO.getStringClaim(AuthUserInfoClaims.RP_PAIRWISE_ID.getValue()))
                .thenReturn(RP_PAIRWISE_ID.getValue());
        when(USER_INFO.getStringClaim(AuthUserInfoClaims.PUBLIC_SUBJECT_ID.getValue()))
                .thenReturn(PUBLIC_SUBJECT_ID.getValue());
        when(USER_INFO.getPhoneNumber()).thenReturn("1234");
        when(USER_INFO.getClaim(
                        AuthUserInfoClaims.VERIFIED_MFA_METHOD_TYPE.getValue(), String.class))
                .thenReturn(MFAMethodType.AUTH_APP.getValue());
        when(USER_INFO.getBooleanClaim(AuthUserInfoClaims.UPLIFT_REQUIRED.getValue()))
                .thenReturn(false);
        when(CONTEXT.getAwsRequestId()).thenReturn("test-request-id");
    }

    @BeforeEach
    void setUp() {
        reset(initiateIPVAuthorisationService);
        reset(logoutService);
        reset(authorizationService);
        reset(noSessionOrchestrationService);

        clearInvocations(orchAuthCodeService);

        when(USER_INFO.getBooleanClaim("new_account")).thenReturn(true);
        when(logoutService.handleReauthenticationFailureLogout(any(), any(), any(), any(), any()))
                .thenAnswer(
                        args -> {
                            var errorRedirectUri = (URI) args.getArgument(4);
                            return new APIGatewayProxyResponseEvent()
                                    .withStatusCode(302)
                                    .withHeaders(
                                            Map.of(
                                                    ResponseHeaders.LOCATION,
                                                    errorRedirectUri.toString()));
                        });

        when(orchAuthCodeService.generateAndSaveAuthorisationCode(
                        anyString(), anyString(), anyString(), anyLong()))
                .thenReturn(AUTH_CODE_RP_TO_ORCH);

        handler =
                new AuthenticationCallbackHandler(
                        configurationService,
                        authorizationService,
                        tokenService,
                        orchSessionService,
                        orchClientSessionService,
                        auditService,
                        userInfoStorageService,
                        cloudwatchMetricsService,
                        orchAuthCodeService,
                        clientService,
                        initiateIPVAuthorisationService,
                        accountInterventionService,
                        logoutService,
                        authFrontend,
                        noSessionOrchestrationService);
        orchSession.resetClientSessions();
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

        var response = handler.handleRequest(event, CONTEXT);

        assertThat(response, hasStatus(302));
        String redirectLocation = response.getHeaders().get("Location");
        assertThat(
                redirectLocation,
                equalTo(REDIRECT_URI + "?code=" + AUTH_CODE_RP_TO_ORCH + "&state=" + RP_STATE));
        verifyUserInfoRequest();

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

        assertAuthorisationCodeGeneratedAndSaved();
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

        var response = handler.handleRequest(event, CONTEXT);

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

        assertNoAuthorisationCodeGeneratedAndSaved();
    }

    @Test
    void
            shouldRedirectToRPWhenNoSessionCookieAndCallToNoSessionOrchestrationServiceReturnsNoSessionEntity()
                    throws NoSessionException {

        var event = new APIGatewayProxyRequestEvent();

        Map<String, String> queryParameters = new HashMap<>();
        queryParameters.put("error", OAuth2Error.ACCESS_DENIED_CODE);
        queryParameters.put("state", STATE.getValue());
        event.setQueryStringParameters(queryParameters);
        event.setHeaders(Collections.emptyMap());

        when(noSessionOrchestrationService.generateNoSessionOrchestrationEntity(queryParameters))
                .thenReturn(
                        new NoSessionEntity(
                                CLIENT_SESSION_ID, OAuth2Error.ACCESS_DENIED, orchClientSession));

        var response = handler.handleRequest(event, CONTEXT);

        var expectedURI =
                new AuthenticationErrorResponse(
                                URI.create(REDIRECT_URI.toString()),
                                OAuth2Error.ACCESS_DENIED,
                                RP_STATE,
                                null)
                        .toURI()
                        .toString();
        assertThat(response, hasStatus(302));
        assertEquals(expectedURI, response.getHeaders().get(ResponseHeaders.LOCATION));
        verify(auditService)
                .submitAuditEvent(
                        OrchestrationAuditableEvent.AUTH_UNSUCCESSFUL_CALLBACK_RESPONSE_RECEIVED,
                        CLIENT_ID.getValue(),
                        TxmaAuditUser.user().withGovukSigninJourneyId(CLIENT_SESSION_ID));

        verifyNoInteractions(tokenService, userInfoStorageService, cloudwatchMetricsService);

        assertNoAuthorisationCodeGeneratedAndSaved();
    }

    @Test
    void
            shouldRedirectToFrontendErrorPageWhenNoSessionCookieButCallToNoSessionOrchestrationServiceThrowsException()
                    throws NoSessionException {
        var event = new APIGatewayProxyRequestEvent();

        Map<String, String> queryParameters = new HashMap<>();
        event.setQueryStringParameters(queryParameters);
        event.setHeaders(Collections.emptyMap());

        doThrow(
                        new NoSessionException(
                                "Session Cookie not present and access_denied or state param missing from error response. NoSessionResponseEnabled: false"))
                .when(noSessionOrchestrationService)
                .generateNoSessionOrchestrationEntity(queryParameters);

        var response = handler.handleRequest(event, CONTEXT);

        assertThat(response, hasStatus(302));
        assertThat(response.getHeaders().get("Location"), equalTo(TEST_FRONTEND_ERROR_URI));

        verifyNoInteractions(
                tokenService, auditService, userInfoStorageService, cloudwatchMetricsService);

        assertNoAuthorisationCodeGeneratedAndSaved();
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

        var response = handler.handleRequest(event, CONTEXT);

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
                        eq(new DestroySessionsRequest(SESSION_ID, List.of(CLIENT_SESSION_ID))),
                        eq(TEST_INTERNAL_COMMON_SUBJECT_ID),
                        eq(event),
                        eq(CLIENT_ID.toString()),
                        any());

        verifyNoInteractions(tokenService, userInfoStorageService, cloudwatchMetricsService);

        assertNoAuthorisationCodeGeneratedAndSaved();
    }

    @Test
    void shouldRedirectToFrontendErrorPageIfTokenRequestIsUnsuccessful() {
        usingValidSession();
        usingValidClientSession();

        var event = new APIGatewayProxyRequestEvent();
        setValidHeadersAndQueryParameters(event);
        when(tokenService.sendTokenRequest(any())).thenReturn(UNSUCCESSFUL_TOKEN_RESPONSE);

        var response = handler.handleRequest(event, CONTEXT);

        assertThat(response, hasStatus(302));
        assertThat(response.getHeaders().get("Location"), equalTo(TEST_FRONTEND_ERROR_URI));

        verifyAuditEvents(
                List.of(
                        OrchestrationAuditableEvent.AUTH_CALLBACK_RESPONSE_RECEIVED,
                        OrchestrationAuditableEvent.AUTH_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED),
                auditService);
        verifyNoInteractions(userInfoStorageService, cloudwatchMetricsService);

        assertNoAuthorisationCodeGeneratedAndSaved();
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

        var response = handler.handleRequest(event, CONTEXT);

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

        assertNoAuthorisationCodeGeneratedAndSaved();
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

        handler.handleRequest(event, CONTEXT);

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

        handler.handleRequest(event, CONTEXT);

        var orchSessionCaptor = ArgumentCaptor.forClass(OrchSessionItem.class);
        verify(orchSessionService, times(3)).updateSession(orchSessionCaptor.capture());
        assertThat(
                OrchSessionItem.AccountState.UNKNOWN,
                equalTo(orchSessionCaptor.getAllValues().get(0).getIsNewAccount()));
    }

    @Test
    void shouldAuditMediumCredentialTrustLevelOn2FARequest()
            throws UnsuccessfulCredentialResponseException {
        usingValidSession();
        var mediumRequestOrchSession =
                new OrchClientSessionItem(
                        CLIENT_SESSION_ID,
                        generateRPAuthRequestForClientSession().toParameters(),
                        null,
                        List.of(
                                VectorOfTrust.of(
                                        CredentialTrustLevel.MEDIUM_LEVEL,
                                        LevelOfConfidence.LOW_LEVEL)),
                        CLIENT_NAME);
        when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(mediumRequestOrchSession));

        usingValidClient();

        var event = new APIGatewayProxyRequestEvent();
        setValidHeadersAndQueryParameters(event);

        when(tokenService.sendTokenRequest(any())).thenReturn(SUCCESSFUL_TOKEN_RESPONSE);

        when(tokenService.sendUserInfoDataRequest(any(HTTPRequest.class))).thenReturn(USER_INFO);

        handler.handleRequest(event, CONTEXT);

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
    void shouldAuditMediumCredentialTrustLevelOn1FARequestWhenAuthReportPreviouslyMediumLevel()
            throws UnsuccessfulCredentialResponseException {
        when(orchSessionService.getSession(SESSION_ID))
                .thenReturn(Optional.of(new OrchSessionItem(SESSION_ID)));
        usingValidClientSession();
        usingValidClient();

        var event = new APIGatewayProxyRequestEvent();
        setValidHeadersAndQueryParameters(event);

        when(tokenService.sendTokenRequest(any())).thenReturn(SUCCESSFUL_TOKEN_RESPONSE);

        when(tokenService.sendUserInfoDataRequest(any(HTTPRequest.class))).thenReturn(USER_INFO);
        when(USER_INFO.getStringClaim(AuthUserInfoClaims.ACHIEVED_CREDENTIAL_STRENGTH.getValue()))
                .thenReturn(CredentialTrustLevel.MEDIUM_LEVEL.name());

        handler.handleRequest(event, CONTEXT);

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

    // TODO: ATO-1218: Following the handler changes, update this method to test
    // shouldRedirectToFrontendErrorPageWhenCallToOrchAuthCodeServiceThrowsException.
    @Test
    void shouldCatchWhenCallToOrchAuthCodeServiceThrowsException()
            throws UnsuccessfulCredentialResponseException {
        usingValidSession();
        usingValidClientSession();
        usingValidClient();

        var event = new APIGatewayProxyRequestEvent();
        setValidHeadersAndQueryParameters(event);

        when(tokenService.sendTokenRequest(any())).thenReturn(SUCCESSFUL_TOKEN_RESPONSE);

        when(tokenService.sendUserInfoDataRequest(any(HTTPRequest.class))).thenReturn(USER_INFO);

        when(orchAuthCodeService.generateAndSaveAuthorisationCode(
                        eq(CLIENT_ID.getValue()),
                        eq(CLIENT_SESSION_ID),
                        eq(TEST_EMAIL_ADDRESS),
                        anyLong()))
                .thenThrow(new OrchAuthCodeException("Some generation error"));

        assertDoesNotThrow(() -> handler.handleRequest(event, CONTEXT));

        verify(orchAuthCodeService, times(1))
                .generateAndSaveAuthorisationCode(
                        eq(CLIENT_ID.getValue()),
                        eq(CLIENT_SESSION_ID),
                        eq(TEST_EMAIL_ADDRESS),
                        anyLong());
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
            handler.handleRequest(event, CONTEXT);

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
            when(USER_INFO.getSubject()).thenReturn(new Subject(TEST_INTERNAL_COMMON_SUBJECT_ID));
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

                var response = handler.handleRequest(event, CONTEXT);

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

                assertAuthorisationCodeGeneratedAndSaved();
            }

            @Test
            void shouldLogoutWhenAccountStatusIsBlocked() {
                AccountIntervention intervention = setUpIntervention(true, false, false, false);

                var event = new APIGatewayProxyRequestEvent();
                setValidHeadersAndQueryParameters(event);

                handler.handleRequest(event, CONTEXT);

                verify(logoutService)
                        .handleAccountInterventionLogout(
                                new DestroySessionsRequest(SESSION_ID, List.of(CLIENT_SESSION_ID)),
                                TEST_INTERNAL_COMMON_SUBJECT_ID,
                                event,
                                CLIENT_ID.toString(),
                                intervention);

                assertNoAuthorisationCodeGeneratedAndSaved();
            }

            @Test
            void shouldLogoutWhenAccountStatusIsSuspendedNoAction() {
                AccountIntervention intervention = setUpIntervention(false, true, false, false);

                var event = new APIGatewayProxyRequestEvent();
                setValidHeadersAndQueryParameters(event);

                handler.handleRequest(event, CONTEXT);

                verify(logoutService)
                        .handleAccountInterventionLogout(
                                new DestroySessionsRequest(SESSION_ID, List.of(CLIENT_SESSION_ID)),
                                TEST_INTERNAL_COMMON_SUBJECT_ID,
                                event,
                                CLIENT_ID.toString(),
                                intervention);

                assertNoAuthorisationCodeGeneratedAndSaved();
            }

            @Test
            void shouldLogoutWhenAccountStatusIsSuspendedResetPassword() {
                AccountIntervention intervention = setUpIntervention(false, true, false, true);

                var event = new APIGatewayProxyRequestEvent();
                setValidHeadersAndQueryParameters(event);

                handler.handleRequest(event, CONTEXT);

                verify(logoutService)
                        .handleAccountInterventionLogout(
                                new DestroySessionsRequest(SESSION_ID, List.of(CLIENT_SESSION_ID)),
                                TEST_INTERNAL_COMMON_SUBJECT_ID,
                                event,
                                CLIENT_ID.toString(),
                                intervention);

                assertNoAuthorisationCodeGeneratedAndSaved();
            }

            @Test
            void shouldRedirectToRpWhenAccountStatusIsSuspendedReproveIdentity() {
                setUpIntervention(false, true, true, false);

                var event = new APIGatewayProxyRequestEvent();
                setValidHeadersAndQueryParameters(event);

                var response = handler.handleRequest(event, CONTEXT);

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

                assertAuthorisationCodeGeneratedAndSaved();
            }

            @Test
            void shouldLogoutWhenAccountStatusIsSuspendedResetPasswordReproveIdentity() {
                AccountIntervention intervention = setUpIntervention(false, true, true, true);

                var event = new APIGatewayProxyRequestEvent();
                setValidHeadersAndQueryParameters(event);

                handler.handleRequest(event, CONTEXT);

                verify(logoutService)
                        .handleAccountInterventionLogout(
                                new DestroySessionsRequest(SESSION_ID, List.of(CLIENT_SESSION_ID)),
                                TEST_INTERNAL_COMMON_SUBJECT_ID,
                                event,
                                CLIENT_ID.getValue(),
                                intervention);

                assertNoAuthorisationCodeGeneratedAndSaved();
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

                handler.handleRequest(event, CONTEXT);

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
                verify(orchSessionService, times(2))
                        .updateSession(argThat(OrchSessionItem::getAuthenticated));

                assertNoAuthorisationCodeGeneratedAndSaved();
            }

            @Test
            void shouldLogoutWhenAccountStatusIsBlocked() {
                AccountIntervention intervention = setUpIntervention(true, false, false, false);

                var event = new APIGatewayProxyRequestEvent();
                setValidHeadersAndQueryParameters(event);

                handler.handleRequest(event, CONTEXT);

                verify(logoutService)
                        .handleAccountInterventionLogout(
                                new DestroySessionsRequest(SESSION_ID, List.of(CLIENT_SESSION_ID)),
                                TEST_INTERNAL_COMMON_SUBJECT_ID,
                                event,
                                CLIENT_ID.getValue(),
                                intervention);
                verifyNoInteractions(initiateIPVAuthorisationService);
                verify(orchSessionService, times(2))
                        .updateSession(argThat(OrchSessionItem::getAuthenticated));

                assertNoAuthorisationCodeGeneratedAndSaved();
            }

            @Test
            void shouldRedirectToIPVWhenAccountStatusIsSuspendedNoAction() {
                boolean reproveIdentity = false;
                setUpIntervention(false, true, reproveIdentity, false);

                var event = new APIGatewayProxyRequestEvent();
                setValidHeadersAndQueryParameters(event);

                handler.handleRequest(event, CONTEXT);

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
                verify(orchSessionService, times(2))
                        .updateSession(argThat(OrchSessionItem::getAuthenticated));

                assertNoAuthorisationCodeGeneratedAndSaved();
            }

            @Test
            void shouldLogoutWhenAccountStatusIsSuspendedResetPassword() {
                AccountIntervention intervention = setUpIntervention(false, true, false, true);

                var event = new APIGatewayProxyRequestEvent();
                setValidHeadersAndQueryParameters(event);

                handler.handleRequest(event, CONTEXT);

                verify(logoutService)
                        .handleAccountInterventionLogout(
                                new DestroySessionsRequest(SESSION_ID, List.of(CLIENT_SESSION_ID)),
                                TEST_INTERNAL_COMMON_SUBJECT_ID,
                                event,
                                CLIENT_ID.toString(),
                                intervention);
                verifyNoInteractions(initiateIPVAuthorisationService);
                verify(orchSessionService, times(2))
                        .updateSession(argThat(OrchSessionItem::getAuthenticated));

                assertNoAuthorisationCodeGeneratedAndSaved();
            }

            @Test
            void shouldRedirectToIPVWhenAccountStatusIsSuspendedReproveIdentity() {
                boolean reproveIdentity = true;
                setUpIntervention(false, true, reproveIdentity, false);

                var event = new APIGatewayProxyRequestEvent();
                setValidHeadersAndQueryParameters(event);

                handler.handleRequest(event, CONTEXT);

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
                verify(orchSessionService, times(2))
                        .updateSession(argThat(OrchSessionItem::getAuthenticated));

                assertNoAuthorisationCodeGeneratedAndSaved();
            }

            @Test
            void shouldLogoutWhenAccountStatusIsSuspendedResetPasswordAndReproveIdentity() {
                AccountIntervention intervention = setUpIntervention(false, true, true, true);

                var event = new APIGatewayProxyRequestEvent();
                setValidHeadersAndQueryParameters(event);

                handler.handleRequest(event, CONTEXT);

                verify(logoutService)
                        .handleAccountInterventionLogout(
                                new DestroySessionsRequest(SESSION_ID, List.of(CLIENT_SESSION_ID)),
                                TEST_INTERNAL_COMMON_SUBJECT_ID,
                                event,
                                CLIENT_ID.toString(),
                                intervention);
                verifyNoInteractions(initiateIPVAuthorisationService);

                assertNoAuthorisationCodeGeneratedAndSaved();
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
            var maxAgeOrchSession = withMaxAgeOrchSession(INTERNAL_COMMON_SUBJECT_ID);
            withPreviousOrchSessionDueToMaxAge();

            when(tokenService.sendTokenRequest(any())).thenReturn(SUCCESSFUL_TOKEN_RESPONSE);
            when(tokenService.sendUserInfoDataRequest(any(HTTPRequest.class)))
                    .thenReturn(USER_INFO);
            when(USER_INFO.getSubject()).thenReturn(new Subject(INTERNAL_COMMON_SUBJECT_ID));

            var event = new APIGatewayProxyRequestEvent();
            setValidHeadersAndQueryParameters(event);
            var response = handler.handleRequest(event, CONTEXT);

            assertThat(response, hasStatus(302));
            String redirectLocation = response.getHeaders().get("Location");
            assertThat(
                    redirectLocation,
                    equalTo(REDIRECT_URI + "?code=" + AUTH_CODE_RP_TO_ORCH + "&state=" + RP_STATE));

            var expectedClientSessions = new ArrayList<>(List.of(CLIENT_SESSION_ID));
            expectedClientSessions.addAll(PREVIOUS_CLIENT_SESSIONS);

            assertEquals(
                    maxAgeOrchSession.getClientSessions(),
                    expectedClientSessions.stream().toList());
            assertNull(maxAgeOrchSession.getPreviousSessionId());
            verify(orchSessionService).getSession(PREVIOUS_SESSION_ID);
            verify(orchSessionService, times(3))
                    .updateSession(
                            argThat(
                                    s ->
                                            s.getPreviousSessionId() == null
                                                    && s.getClientSessions().size() == 4
                                                    && s.getClientSessions()
                                                            .equals(expectedClientSessions)));
        }

        @Test
        void itDoesNotAssignClientSessionsIfItCannotFindThePreviousOrchSession()
                throws UnsuccessfulCredentialResponseException {
            var maxAgeOrchSession = withMaxAgeOrchSession(INTERNAL_COMMON_SUBJECT_ID);
            withNoPreviousOrchSession();

            when(tokenService.sendTokenRequest(any())).thenReturn(SUCCESSFUL_TOKEN_RESPONSE);
            when(tokenService.sendUserInfoDataRequest(any(HTTPRequest.class)))
                    .thenReturn(USER_INFO);
            when(USER_INFO.getSubject()).thenReturn(new Subject(INTERNAL_COMMON_SUBJECT_ID));

            var event = new APIGatewayProxyRequestEvent();
            setValidHeadersAndQueryParameters(event);
            var response = handler.handleRequest(event, CONTEXT);

            assertThat(response, hasStatus(302));
            String redirectLocation = response.getHeaders().get("Location");
            assertThat(
                    redirectLocation,
                    equalTo(REDIRECT_URI + "?code=" + AUTH_CODE_RP_TO_ORCH + "&state=" + RP_STATE));

            assertEquals(List.of(CLIENT_SESSION_ID), maxAgeOrchSession.getClientSessions());
            assertNull(maxAgeOrchSession.getPreviousSessionId());
            verify(orchSessionService).getSession(PREVIOUS_SESSION_ID);
            verify(orchSessionService, times(3))
                    .updateSession(
                            argThat(
                                    s ->
                                            s.getPreviousSessionId() == null
                                                    && s.getClientSessions().size() == 1
                                                    && s.getClientSessions()
                                                            .equals(List.of(CLIENT_SESSION_ID))));
        }

        @Test
        void
                itSendsBackChannelLogoutNotificationForThePreviousSessionIfTheInternalCommonSubjectIdsDoNotMatch()
                        throws UnsuccessfulCredentialResponseException {
            var maxAgeOrchSession = withMaxAgeOrchSession(INTERNAL_COMMON_SUBJECT_ID);
            var previousOrchSession = withPreviousOrchSessionDueToMaxAge();

            when(tokenService.sendTokenRequest(any())).thenReturn(SUCCESSFUL_TOKEN_RESPONSE);
            when(tokenService.sendUserInfoDataRequest(any(HTTPRequest.class)))
                    .thenReturn(USER_INFO);
            when(USER_INFO.getSubject())
                    .thenReturn(new Subject(DIFFERENT_INTERNAL_COMMON_SUBJECT_ID));

            var event = new APIGatewayProxyRequestEvent();
            setValidHeadersAndQueryParameters(event);
            var response = handler.handleRequest(event, CONTEXT);

            assertThat(response, hasStatus(302));
            String redirectLocation = response.getHeaders().get("Location");
            assertThat(
                    redirectLocation,
                    equalTo(REDIRECT_URI + "?code=" + AUTH_CODE_RP_TO_ORCH + "&state=" + RP_STATE));

            assertEquals(List.of(CLIENT_SESSION_ID), maxAgeOrchSession.getClientSessions());
            assertNull(maxAgeOrchSession.getPreviousSessionId());
            verify(orchSessionService).getSession(PREVIOUS_SESSION_ID);
            verify(orchSessionService, times(3))
                    .updateSession(
                            argThat(
                                    s ->
                                            s.getPreviousSessionId() == null
                                                    && s.getClientSessions().size() == 1));

            verify(logoutService, times(1))
                    .handleMaxAgeLogout(
                            eq(
                                    new DestroySessionsRequest(
                                            PREVIOUS_SESSION_ID, PREVIOUS_CLIENT_SESSIONS)),
                            eq(previousOrchSession),
                            any(TxmaAuditUser.class));
        }

        private OrchSessionItem withPreviousOrchSessionDueToMaxAge() {
            var previousOrchSession =
                    new OrchSessionItem(PREVIOUS_SESSION_ID)
                            .withInternalCommonSubjectId(INTERNAL_COMMON_SUBJECT_ID);
            PREVIOUS_CLIENT_SESSIONS.forEach(previousOrchSession::addClientSession);
            when(orchSessionService.getSession(PREVIOUS_SESSION_ID))
                    .thenReturn(Optional.of(previousOrchSession));
            return previousOrchSession;
        }

        private void withNoPreviousOrchSession() {
            when(orchSessionService.getSession(PREVIOUS_SESSION_ID)).thenReturn(Optional.empty());
        }

        private OrchSessionItem withMaxAgeOrchSession(String internalCommonSubjectId) {
            var maxAgeOrchSession =
                    new OrchSessionItem(SESSION_ID)
                            .withPreviousSessionId(PREVIOUS_SESSION_ID)
                            .withInternalCommonSubjectId(internalCommonSubjectId)
                            .addClientSession(CLIENT_SESSION_ID);
            when(orchSessionService.getSession(SESSION_ID))
                    .thenReturn(Optional.of(maxAgeOrchSession));
            return maxAgeOrchSession;
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
        when(orchSessionService.getSession(SESSION_ID)).thenReturn(Optional.of(orchSession));
    }

    private void usingValidClientSession() {
        when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(orchClientSession));
        orchSession.addClientSession(CLIENT_SESSION_ID);
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

    private void assertAuthorisationCodeGeneratedAndSaved() {
        verify(orchAuthCodeService, times(1))
                .generateAndSaveAuthorisationCode(
                        eq(CLIENT_ID.getValue()),
                        eq(CLIENT_SESSION_ID),
                        eq(TEST_EMAIL_ADDRESS),
                        anyLong());
    }

    private void assertNoAuthorisationCodeGeneratedAndSaved() {
        verify(orchAuthCodeService, times(0))
                .generateAndSaveAuthorisationCode(anyString(), anyString(), anyString(), anyLong());
    }

    private void assertOrchSessionUpdated() {
        var orchSessionCaptor = ArgumentCaptor.forClass(OrchSessionItem.class);
        verify(orchSessionService, times(3)).updateSession(orchSessionCaptor.capture());
        assertTrue(orchSessionCaptor.getAllValues().get(0).getAuthenticated());
        assertThat(
                orchSessionCaptor.getAllValues().get(0).getIsNewAccount(),
                equalTo(OrchSessionItem.AccountState.NEW));
    }

    private void assertClientSessionUpdated() {
        var orchClientSessionCaptor = ArgumentCaptor.forClass(OrchClientSessionItem.class);
        verify(orchClientSessionService, times(1))
                .updateStoredClientSession(orchClientSessionCaptor.capture());
        assertEquals(
                RP_PAIRWISE_ID.getValue(),
                orchClientSessionCaptor
                        .getValue()
                        .getCorrectPairwiseIdGivenSubjectType(SubjectType.PAIRWISE.toString()));
        assertEquals(
                PUBLIC_SUBJECT_ID.getValue(),
                orchClientSessionCaptor
                        .getValue()
                        .getCorrectPairwiseIdGivenSubjectType(SubjectType.PUBLIC.toString()));
    }

    private void clientSessionWithCredentialTrustValue(CredentialTrustLevel credentialTrustLevel) {
        var orchClientSessionWithCredentialTrustLevel =
                createOrchClientSession(credentialTrustLevel);
        when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(orchClientSessionWithCredentialTrustLevel));
    }

    private OrchClientSessionItem createOrchClientSession(
            CredentialTrustLevel credentialTrustLevel) {
        return new OrchClientSessionItem(
                CLIENT_SESSION_ID,
                generateRPAuthRequestForClientSession().toParameters(),
                null,
                List.of(VectorOfTrust.of(credentialTrustLevel, LevelOfConfidence.LOW_LEVEL)),
                CLIENT_NAME);
    }
}
