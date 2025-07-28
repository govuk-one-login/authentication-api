package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.oidc.domain.OidcAuditableEvent;
import uk.gov.di.authentication.oidc.entity.AuthCodeResponse;
import uk.gov.di.authentication.oidc.services.OrchestrationAuthorizationService;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.CustomScopeValue;
import uk.gov.di.orchestration.shared.entity.ErrorResponse;
import uk.gov.di.orchestration.shared.entity.MFAMethodType;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.OrchAuthCodeException;
import uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.helpers.PersistentIdHelper;
import uk.gov.di.orchestration.shared.helpers.SaltHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.AuthCodeResponseGenerationService;
import uk.gov.di.orchestration.shared.services.AuthenticationUserInfoStorageService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.OrchAuthCodeService;
import uk.gov.di.orchestration.shared.services.OrchClientSessionService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.sharedtest.helper.KeyPairHelper;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.oidc.helper.RequestObjectTestHelper.generateSignedJWT;
import static uk.gov.di.orchestration.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.orchestration.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;
import static uk.gov.di.orchestration.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.orchestration.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthCodeHandlerTest {
    private final AuthCodeResponseGenerationService authCodeResponseService =
            mock(AuthCodeResponseGenerationService.class);
    private final AuditService auditService = mock(AuditService.class);

    private final OrchAuthCodeService orchAuthCodeService = mock(OrchAuthCodeService.class);
    private final OrchClientSessionItem orchClientSession = mock(OrchClientSessionItem.class);
    private final OrchClientSessionService orchClientSessionService =
            mock(OrchClientSessionService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final Context context = mock(Context.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final OrchestrationAuthorizationService orchestrationAuthorizationService =
            mock(OrchestrationAuthorizationService.class);
    private final OrchSessionService orchSessionService = mock(OrchSessionService.class);
    private final AuthenticationUserInfoStorageService authUserInfoService =
            mock(AuthenticationUserInfoStorageService.class);
    private final VectorOfTrust vectorOfTrust = mock(VectorOfTrust.class);

    private static final String SESSION_ID = IdGenerator.generate();
    private static final String CLIENT_SESSION_ID = IdGenerator.generate();
    private static final String PERSISTENT_SESSION_ID = IdGenerator.generate();
    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String PHONE_NUMBER = "012345678902";
    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final Subject SUBJECT = new Subject();
    private static final String DOC_APP_SUBJECT_ID = "docAppSubjectId";
    private static final String INTERNAL_COMMON_SUBJECT_ID = "internalCommonSubjectId";
    private static final ClientID CLIENT_ID = new ClientID();
    private static final String CLIENT_NAME = "test-client-name";
    private static final String AUDIENCE = "oidc-audience";
    private static final State STATE = new State();
    private static final Nonce NONCE = new Nonce();
    private static final byte[] SALT = SaltHelper.generateNewSalt();
    private static final String BASE_64_ENCODED_SALT = Base64.getEncoder().encodeToString(SALT);
    private static final Json objectMapper = SerializationService.getInstance();
    private AuthCodeHandler handler;

    private final OrchSessionItem orchSession =
            new OrchSessionItem(SESSION_ID)
                    .withAccountState(OrchSessionItem.AccountState.NEW)
                    .withInternalCommonSubjectId(INTERNAL_COMMON_SUBJECT_ID)
                    .withAuthTime(12345L)
                    .addClientSession(CLIENT_SESSION_ID);

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(AuthCodeHandler.class);

    @AfterEach
    public void tearDown() {
        assertThat(
                logging.events(),
                not(
                        hasItem(
                                withMessageContaining(
                                        SESSION_ID,
                                        CLIENT_SESSION_ID,
                                        PERSISTENT_SESSION_ID,
                                        EMAIL,
                                        CLIENT_ID.getValue()))));
    }

    @BeforeEach
    void setUp() {
        handler =
                new AuthCodeHandler(
                        orchSessionService,
                        authUserInfoService,
                        authCodeResponseService,
                        orchAuthCodeService,
                        orchestrationAuthorizationService,
                        orchClientSessionService,
                        auditService,
                        cloudwatchMetricsService,
                        configurationService,
                        dynamoClientService);
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
        when(configurationService.getEnvironment()).thenReturn("unit-test");
        when(configurationService.getInternalSectorURI()).thenReturn(INTERNAL_SECTOR_URI);
        doAnswer(
                        (i) -> {
                            orchSession
                                    .withAuthenticated(true)
                                    .setIsNewAccount(OrchSessionItem.AccountState.EXISTING);
                            return null;
                        })
                .when(authCodeResponseService)
                .saveSession(false, orchSessionService, orchSession);
        when(dynamoClientService.getClient(anyString()))
                .thenReturn(
                        Optional.of(
                                new ClientRegistry()
                                        .withClientID(CLIENT_ID.getValue())
                                        .withSubjectType("pairwise")));
    }

    private static Stream<Arguments> upliftTestParameters() {
        return Stream.of(
                arguments(null, LOW_LEVEL, LOW_LEVEL, MFAMethodType.AUTH_APP),
                arguments(LOW_LEVEL, LOW_LEVEL, LOW_LEVEL, MFAMethodType.AUTH_APP),
                arguments(MEDIUM_LEVEL, MEDIUM_LEVEL, MEDIUM_LEVEL, MFAMethodType.SMS),
                arguments(LOW_LEVEL, MEDIUM_LEVEL, MEDIUM_LEVEL, MFAMethodType.SMS),
                arguments(MEDIUM_LEVEL, LOW_LEVEL, MEDIUM_LEVEL, MFAMethodType.AUTH_APP));
    }

    @ParameterizedTest
    @MethodSource("upliftTestParameters")
    void shouldGenerateSuccessfulAuthResponseAndUpliftAsNecessary(
            CredentialTrustLevel initialLevel,
            CredentialTrustLevel requestedLevel,
            CredentialTrustLevel finalLevel,
            MFAMethodType mfaMethodType)
            throws Json.JsonException, JOSEException, ParseException {
        generateAuthUserInfo();
        if (Objects.nonNull(mfaMethodType)) {
            when(authCodeResponseService.getDimensions(
                            eq(orchSession),
                            eq(CLIENT_NAME),
                            eq(CLIENT_ID.getValue()),
                            anyBoolean(),
                            anyBoolean()))
                    .thenReturn(
                            new HashMap<>(
                                    Map.of(
                                            "Account",
                                            "NEW",
                                            "Environment",
                                            "unit-test",
                                            "Client",
                                            CLIENT_ID.getValue(),
                                            "IsTest",
                                            "false",
                                            "IsDocApp",
                                            Boolean.toString(false),
                                            "MfaMethod",
                                            mfaMethodType.getValue(),
                                            "ClientName",
                                            CLIENT_NAME)));
        }
        doCallRealMethod()
                .when(authCodeResponseService)
                .processVectorOfTrust(any(OrchClientSessionItem.class), any());
        var authorizationCode = new AuthorizationCode();
        var authRequest = generateValidSessionAndAuthRequest(requestedLevel, false);
        orchSession.setIsNewAccount(OrchSessionItem.AccountState.NEW);
        var authSuccessResponse =
                new AuthenticationSuccessResponse(
                        authRequest.getRedirectionURI(),
                        authorizationCode,
                        null,
                        null,
                        authRequest.getState(),
                        null,
                        authRequest.getResponseMode());
        when(orchestrationAuthorizationService.isClientRedirectUriValid(
                        (ClientRegistry) any(), eq(REDIRECT_URI)))
                .thenReturn(true);
        when(orchAuthCodeService.generateAndSaveAuthorisationCode(
                        eq(CLIENT_ID.getValue()),
                        eq(CLIENT_SESSION_ID),
                        eq(EMAIL),
                        any(Long.class)))
                .thenReturn(authorizationCode);
        when(orchestrationAuthorizationService.generateSuccessfulAuthResponse(
                        any(AuthenticationRequest.class),
                        any(AuthorizationCode.class),
                        any(URI.class),
                        any(State.class)))
                .thenReturn(authSuccessResponse);
        when(orchClientSession.getVtrList()).thenReturn(List.of(new VectorOfTrust(requestedLevel)));
        when(orchClientSession.getVtrLocsAsCommaSeparatedString()).thenReturn("P0");
        when(orchClientSession.getCorrectPairwiseIdGivenSubjectType(anyString()))
                .thenReturn(
                        ClientSubjectHelper.calculatePairwiseIdentifier(
                                SUBJECT.getValue(), "rp-sector-uri", SALT));

        var response = generateApiRequest();

        assertThat(response, hasStatus(200));
        var authCodeResponse = objectMapper.readValue(response.getBody(), AuthCodeResponse.class);
        assertThat(authCodeResponse.getLocation(), equalTo(authSuccessResponse.toURI().toString()));
        assertTrue(orchSession.getAuthenticated());

        verify(authCodeResponseService, times(1))
                .saveSession(anyBoolean(), eq(orchSessionService), eq(orchSession));

        var expectedRpPairwiseId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), "rp-sector-uri", SALT);

        verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.AUTH_CODE_ISSUED,
                        CLIENT_ID.getValue(),
                        TxmaAuditUser.user()
                                .withGovukSigninJourneyId(CLIENT_SESSION_ID)
                                .withSessionId(SESSION_ID)
                                .withUserId(INTERNAL_COMMON_SUBJECT_ID)
                                .withEmail(EMAIL)
                                .withIpAddress("123.123.123.123")
                                .withPersistentSessionId(PERSISTENT_SESSION_ID),
                        pair("internalSubjectId", SUBJECT.getValue()),
                        pair("isNewAccount", OrchSessionItem.AccountState.NEW),
                        pair("rpPairwiseId", expectedRpPairwiseId),
                        pair("authCode", authorizationCode),
                        pair("nonce", NONCE.getValue()));

        assertAuthorisationCodeGeneratedAndSaved(EMAIL);

        var dimensions =
                Map.of(
                        "Account",
                        "NEW",
                        "Environment",
                        "unit-test",
                        "Client",
                        CLIENT_ID.getValue(),
                        "IsTest",
                        "false",
                        "IsDocApp",
                        Boolean.toString(false),
                        "MfaMethod",
                        mfaMethodType.getValue(),
                        "ClientName",
                        CLIENT_NAME,
                        "MfaRequired",
                        requestedLevel.equals(LOW_LEVEL) ? "No" : "Yes",
                        "RequestedLevelOfConfidence",
                        "P0");

        verify(cloudwatchMetricsService).incrementCounter("SignIn", dimensions);

        assertAuthorisationCodeGeneratedAndSaved(EMAIL);
    }

    private static Stream<CredentialTrustLevel> docAppTestParameters() {
        return Stream.of(LOW_LEVEL, MEDIUM_LEVEL);
    }

    @ParameterizedTest
    @MethodSource("docAppTestParameters")
    void shouldGenerateSuccessfulAuthResponseForDocAppJourney(CredentialTrustLevel requestedLevel)
            throws Json.JsonException, JOSEException {
        var authorizationCode = new AuthorizationCode();
        var authRequest = generateValidSessionAndAuthRequest(requestedLevel, true);
        var authSuccessResponse =
                new AuthenticationSuccessResponse(
                        authRequest.getRedirectionURI(),
                        authorizationCode,
                        null,
                        null,
                        authRequest.getState(),
                        null,
                        authRequest.getResponseMode());

        when(orchClientSession.getDocAppSubjectId()).thenReturn(DOC_APP_SUBJECT_ID);
        when(orchClientSession.getVtrList()).thenReturn(List.of(new VectorOfTrust(requestedLevel)));
        when(orchestrationAuthorizationService.isClientRedirectUriValid(
                        (ClientRegistry) any(), eq(REDIRECT_URI)))
                .thenReturn(true);
        when(orchAuthCodeService.generateAndSaveAuthorisationCode(
                        eq(CLIENT_ID.getValue()), eq(CLIENT_SESSION_ID), eq(null), any(Long.class)))
                .thenReturn(authorizationCode);
        when(authCodeResponseService.getDimensions(
                        eq(orchSession),
                        eq(CLIENT_NAME),
                        eq(CLIENT_ID.getValue()),
                        anyBoolean(),
                        eq(true)))
                .thenReturn(
                        Map.of(
                                "Account",
                                "UNKNOWN",
                                "Environment",
                                "unit-test",
                                "Client",
                                CLIENT_ID.getValue(),
                                "IsTest",
                                "false",
                                "IsDocApp",
                                Boolean.toString(true),
                                "ClientName",
                                CLIENT_NAME));
        when(orchestrationAuthorizationService.generateSuccessfulAuthResponse(
                        any(AuthenticationRequest.class),
                        any(AuthorizationCode.class),
                        any(URI.class),
                        any(State.class)))
                .thenReturn(authSuccessResponse);

        var response = generateApiRequest();

        assertThat(response, hasStatus(200));
        var authCodeResponse = objectMapper.readValue(response.getBody(), AuthCodeResponse.class);
        assertThat(authCodeResponse.getLocation(), equalTo(authSuccessResponse.toURI().toString()));
        assertFalse(orchSession.getAuthenticated());
        verify(authCodeResponseService, times(1))
                .saveSession(
                        anyBoolean(), any(OrchSessionService.class), any(OrchSessionItem.class));
        verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.AUTH_CODE_ISSUED,
                        CLIENT_ID.getValue(),
                        TxmaAuditUser.user()
                                .withGovukSigninJourneyId(CLIENT_SESSION_ID)
                                .withSessionId(SESSION_ID)
                                .withUserId(DOC_APP_SUBJECT_ID)
                                .withEmail("")
                                .withIpAddress("123.123.123.123")
                                .withPersistentSessionId(PERSISTENT_SESSION_ID),
                        pair("internalSubjectId", AuditService.UNKNOWN),
                        pair("isNewAccount", OrchSessionItem.AccountState.NEW),
                        pair("rpPairwiseId", AuditService.UNKNOWN),
                        pair("authCode", authorizationCode),
                        pair("nonce", NONCE.getValue()));

        assertAuthorisationCodeGeneratedAndSaved(null);

        var expectedDimensions =
                Map.of(
                        "Account",
                        "UNKNOWN",
                        "Environment",
                        "unit-test",
                        "Client",
                        CLIENT_ID.getValue(),
                        "IsTest",
                        "false",
                        "IsDocApp",
                        Boolean.toString(true),
                        "ClientName",
                        CLIENT_NAME);

        verify(cloudwatchMetricsService).incrementCounter("SignIn", expectedDimensions);

        assertAuthorisationCodeGeneratedAndSaved(null);
    }

    @Test
    void shouldGenerateErrorResponseWhenSessionIsNotFound() {
        APIGatewayProxyResponseEvent response = generateApiRequest();

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1000));

        verifyNoInteractions(auditService);

        assertNoAuthorisationCodeGeneratedAndSaved();
    }

    @Test
    void shouldGenerateErrorResponseWhenOrchSessionIsNotFound() {
        when(orchClientSessionService.getClientSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(orchClientSession));
        when(orchClientSession.getClientName()).thenReturn(CLIENT_NAME);

        APIGatewayProxyResponseEvent response = generateApiRequest();

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1000));

        verifyNoInteractions(auditService);

        assertNoAuthorisationCodeGeneratedAndSaved();
    }

    @Test
    void shouldGenerateErrorResponseWhenRedirectUriIsInvalid()
            throws JOSEException, ParseException {
        generateAuthUserInfo();
        generateValidSessionAndAuthRequest(MEDIUM_LEVEL, false);
        when(orchestrationAuthorizationService.isClientRedirectUriValid(
                        (ClientRegistry) any(), eq(REDIRECT_URI)))
                .thenReturn(false);
        APIGatewayProxyResponseEvent response = generateApiRequest();

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1016));

        verifyNoInteractions(auditService);

        assertNoAuthorisationCodeGeneratedAndSaved();
    }

    @Test
    void shouldGenerateErrorResponseWhenClientIsNotFound()
            throws Json.JsonException, JOSEException, ParseException {
        generateAuthUserInfo();
        AuthenticationErrorResponse authenticationErrorResponse =
                new AuthenticationErrorResponse(
                        REDIRECT_URI, OAuth2Error.INVALID_CLIENT, null, null);
        when(orchestrationAuthorizationService.generateAuthenticationErrorResponse(
                        any(AuthenticationRequest.class),
                        eq(OAuth2Error.INVALID_CLIENT),
                        any(URI.class),
                        any(State.class)))
                .thenReturn(authenticationErrorResponse);
        generateValidSessionAndAuthRequest(MEDIUM_LEVEL, false);
        when(dynamoClientService.getClient(anyString())).thenReturn(Optional.empty());

        APIGatewayProxyResponseEvent response = generateApiRequest();

        assertThat(response, hasStatus(500));
        AuthCodeResponse authCodeResponse =
                objectMapper.readValue(response.getBody(), AuthCodeResponse.class);
        assertThat(
                authCodeResponse.getLocation(),
                equalTo(
                        "http://localhost/redirect?error=invalid_client&error_description=Client+authentication+failed"));

        verifyNoInteractions(auditService);

        assertNoAuthorisationCodeGeneratedAndSaved();
    }

    @Test
    void shouldGenerateErrorResponseWhenAuthUserInfoIsNotFound()
            throws Json.JsonException, JOSEException {
        when(orchestrationAuthorizationService.isClientRedirectUriValid(
                        (ClientRegistry) any(), eq(REDIRECT_URI)))
                .thenReturn(true);
        when(orchClientSession.getVtrList()).thenReturn(List.of(new VectorOfTrust(MEDIUM_LEVEL)));
        when(orchClientSessionService.getClientSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(orchClientSession));
        when(orchClientSession.getClientName()).thenReturn(CLIENT_NAME);
        when(orchSessionService.getSession(anyString())).thenReturn(Optional.of(orchSession));
        AuthenticationErrorResponse authenticationErrorResponse =
                new AuthenticationErrorResponse(
                        REDIRECT_URI, OAuth2Error.ACCESS_DENIED, null, null);
        when(orchestrationAuthorizationService.generateAuthenticationErrorResponse(
                        any(AuthenticationRequest.class),
                        eq(OAuth2Error.ACCESS_DENIED),
                        any(URI.class),
                        any(State.class)))
                .thenReturn(authenticationErrorResponse);
        generateValidSessionAndAuthRequest(MEDIUM_LEVEL, false);

        APIGatewayProxyResponseEvent response = generateApiRequest();

        assertThat(response, hasStatus(400));
        AuthCodeResponse authCodeResponse =
                objectMapper.readValue(response.getBody(), AuthCodeResponse.class);
        assertThat(
                authCodeResponse.getLocation(),
                equalTo(
                        "http://localhost/redirect?error=access_denied&error_description=Access+denied+by+resource+owner+or+authorization+server"));

        verifyNoInteractions(auditService);

        assertNoAuthorisationCodeGeneratedAndSaved();
    }

    @Test
    void shouldGenerateErrorResponseWhenOrchSessionHasNoInternalCommonSubjectId()
            throws Json.JsonException, JOSEException, ParseException {
        generateAuthUserInfo();
        when(orchClientSession.getVtrList()).thenReturn(List.of(new VectorOfTrust(MEDIUM_LEVEL)));
        when(orchestrationAuthorizationService.isClientRedirectUriValid(
                        (ClientRegistry) any(), eq(REDIRECT_URI)))
                .thenReturn(true);
        when(orchClientSessionService.getClientSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(orchClientSession));
        when(orchClientSession.getClientName()).thenReturn(CLIENT_NAME);
        generateValidSessionAndAuthRequest(MEDIUM_LEVEL, false);
        when(orchSessionService.getSession(anyString()))
                .thenReturn(
                        Optional.of(
                                new OrchSessionItem(SESSION_ID)
                                        .withAccountState(OrchSessionItem.AccountState.NEW)
                                        .withAuthTime(12345L)));
        AuthenticationErrorResponse authenticationErrorResponse =
                new AuthenticationErrorResponse(
                        REDIRECT_URI, OAuth2Error.ACCESS_DENIED, null, null);
        when(orchestrationAuthorizationService.generateAuthenticationErrorResponse(
                        any(AuthenticationRequest.class),
                        eq(OAuth2Error.ACCESS_DENIED),
                        any(URI.class),
                        any(State.class)))
                .thenReturn(authenticationErrorResponse);

        APIGatewayProxyResponseEvent response = generateApiRequest();

        assertThat(response, hasStatus(400));
        AuthCodeResponse authCodeResponse =
                objectMapper.readValue(response.getBody(), AuthCodeResponse.class);
        assertThat(
                authCodeResponse.getLocation(),
                equalTo(
                        "http://localhost/redirect?error=access_denied&error_description=Access+denied+by+resource+owner+or+authorization+server"));

        verifyNoInteractions(auditService);

        assertNoAuthorisationCodeGeneratedAndSaved();
    }

    @Test
    void shouldGenerateErrorResponseIfUnableToParseAuthRequest() throws Json.JsonException {
        AuthenticationErrorResponse authenticationErrorResponse =
                new AuthenticationErrorResponse(
                        REDIRECT_URI, OAuth2Error.INVALID_REQUEST, null, null);
        when(orchestrationAuthorizationService.generateAuthenticationErrorResponse(
                        eq(REDIRECT_URI),
                        isNull(),
                        any(ResponseMode.class),
                        eq(OAuth2Error.INVALID_REQUEST)))
                .thenReturn(authenticationErrorResponse);
        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put("redirect_uri", singletonList("http://localhost/redirect"));
        customParams.put("client_id", singletonList(new ClientID().toString()));
        generateValidSession(customParams, MEDIUM_LEVEL);
        APIGatewayProxyResponseEvent response = generateApiRequest();

        assertThat(response, hasStatus(400));
        AuthCodeResponse authCodeResponse =
                objectMapper.readValue(response.getBody(), AuthCodeResponse.class);
        assertThat(
                authCodeResponse.getLocation(),
                equalTo(
                        "http://localhost/redirect?error=invalid_request&error_description=Invalid+request"));

        verifyNoInteractions(auditService);

        assertNoAuthorisationCodeGeneratedAndSaved();
    }

    @Test
    void shouldReturn400IfSessionIdMissing() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1000));

        verifyNoInteractions(auditService);

        assertNoAuthorisationCodeGeneratedAndSaved();
    }

    @Test
    void shouldReturn400IfClientSessionIdMissing() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(
                Map.of(
                        "Session-Id",
                        SESSION_ID,
                        PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                        PERSISTENT_SESSION_ID));
        when(orchSessionService.getSession(anyString())).thenReturn(Optional.of(orchSession));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1018));

        verifyNoInteractions(auditService);

        assertNoAuthorisationCodeGeneratedAndSaved();
    }

    @Test
    void shouldGenerateErrorResponseWhenAuthCodeGenerationThrowsException()
            throws ParseException, JOSEException {
        generateAuthUserInfo();

        orchSession.withAccountState(OrchSessionItem.AccountState.UNKNOWN);

        when(orchestrationAuthorizationService.isClientRedirectUriValid(
                        (ClientRegistry) any(), eq(REDIRECT_URI)))
                .thenReturn(true);
        when(orchClientSession.getVtrList()).thenReturn(List.of(new VectorOfTrust(MEDIUM_LEVEL)));

        when(orchAuthCodeService.generateAndSaveAuthorisationCode(
                        eq(CLIENT_ID.getValue()), eq(CLIENT_SESSION_ID), eq(EMAIL), anyLong()))
                .thenThrow(new OrchAuthCodeException("Some error during auth code generation."));

        generateValidSessionAndAuthRequest(MEDIUM_LEVEL, false);

        var response = generateApiRequest();

        assertThat(response, hasStatus(500));
        assertThat(response, hasBody("Internal server error"));

        assertAuthorisationCodeGeneratedAndSaved(EMAIL);
    }

    @Test
    void shouldUpdateOrchSession() throws JOSEException, ParseException {
        generateAuthUserInfo();

        var authorizationCode = new AuthorizationCode();
        var authRequest = generateValidSessionAndAuthRequest(MEDIUM_LEVEL, false);

        orchSession.withAccountState(OrchSessionItem.AccountState.UNKNOWN);
        var authSuccessResponse =
                new AuthenticationSuccessResponse(
                        authRequest.getRedirectionURI(),
                        authorizationCode,
                        null,
                        null,
                        authRequest.getState(),
                        null,
                        authRequest.getResponseMode());

        when(orchClientSession.getDocAppSubjectId()).thenReturn(DOC_APP_SUBJECT_ID);
        when(orchClientSession.getVtrList()).thenReturn(List.of(new VectorOfTrust(MEDIUM_LEVEL)));
        when(orchestrationAuthorizationService.isClientRedirectUriValid(
                        (ClientRegistry) any(), eq(REDIRECT_URI)))
                .thenReturn(true);

        // TODO: Stop here in new test.

        when(orchAuthCodeService.generateAndSaveAuthorisationCode(
                        eq(CLIENT_ID.getValue()), eq(CLIENT_SESSION_ID), eq(EMAIL), anyLong()))
                .thenReturn(authorizationCode);
        when(authCodeResponseService.getDimensions(
                        eq(orchSession),
                        eq(CLIENT_NAME),
                        eq(CLIENT_ID.getValue()),
                        anyBoolean(),
                        eq(true)))
                .thenReturn(
                        Map.of(
                                "Account",
                                "UNKNOWN",
                                "Environment",
                                "unit-test",
                                "Client",
                                CLIENT_ID.getValue(),
                                "IsTest",
                                "false",
                                "IsDocApp",
                                Boolean.toString(true),
                                "ClientName",
                                CLIENT_NAME));
        when(orchestrationAuthorizationService.generateSuccessfulAuthResponse(
                        any(AuthenticationRequest.class),
                        any(AuthorizationCode.class),
                        any(URI.class),
                        any(State.class)))
                .thenReturn(authSuccessResponse);

        var response = generateApiRequest();

        assertThat(response, hasStatus(200));
        verify(authCodeResponseService, times(1))
                .saveSession(
                        anyBoolean(), any(OrchSessionService.class), any(OrchSessionItem.class));
    }

    private AuthenticationRequest generateValidSessionAndAuthRequest(
            CredentialTrustLevel requestedLevel, boolean docAppJourney) throws JOSEException {
        AuthenticationRequest authRequest;
        if (docAppJourney) {
            authRequest = generateRequestObjectAuthRequest();
        } else {
            authRequest =
                    new AuthenticationRequest.Builder(
                                    new ResponseType(ResponseType.Value.CODE),
                                    new Scope(OIDCScopeValue.OPENID),
                                    CLIENT_ID,
                                    REDIRECT_URI)
                            .state(STATE)
                            .nonce(NONCE)
                            .build();
        }
        generateValidSession(authRequest.toParameters(), requestedLevel);
        return authRequest;
    }

    private void generateValidSession(
            Map<String, List<String>> authRequestParams, CredentialTrustLevel requestedLevel) {
        when(orchSessionService.getSession(anyString())).thenReturn(Optional.of(orchSession));
        when(orchClientSessionService.getClientSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(orchClientSession));
        when(vectorOfTrust.getCredentialTrustLevel()).thenReturn(requestedLevel);
        when(orchClientSession.getAuthRequestParams()).thenReturn(authRequestParams);
        when(orchClientSession.getClientName()).thenReturn(CLIENT_NAME);
    }

    private APIGatewayProxyResponseEvent generateApiRequest() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(
                Map.of(
                        "Session-Id",
                        SESSION_ID,
                        "Client-Session-Id",
                        CLIENT_SESSION_ID,
                        PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                        PERSISTENT_SESSION_ID));

        return handler.handleRequest(event, context);
    }

    private static AuthenticationRequest generateRequestObjectAuthRequest() throws JOSEException {
        var keyPair = KeyPairHelper.generateRsaKeyPair();
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI.toString())
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", CustomScopeValue.DOC_CHECKING_APP.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("state", STATE.getValue())
                        .claim("nonce", NONCE.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);
        var scope = new Scope(OIDCScopeValue.OPENID, CustomScopeValue.DOC_CHECKING_APP);
        return new AuthenticationRequest.Builder(ResponseType.CODE, scope, CLIENT_ID, REDIRECT_URI)
                .state(STATE)
                .nonce(NONCE)
                .requestObject(signedJWT)
                .build();
    }

    private void generateAuthUserInfo() throws ParseException {
        var authUserInfo =
                new UserInfo(
                        new JSONObject(
                                Map.of(
                                        "sub",
                                        INTERNAL_COMMON_SUBJECT_ID,
                                        "client_session_id",
                                        CLIENT_SESSION_ID,
                                        "email",
                                        EMAIL,
                                        "phone_number",
                                        PHONE_NUMBER,
                                        "salt",
                                        BASE_64_ENCODED_SALT,
                                        "local_account_id",
                                        SUBJECT.getValue())));
        when(authUserInfoService.getAuthenticationUserInfo(
                        INTERNAL_COMMON_SUBJECT_ID, CLIENT_SESSION_ID))
                .thenReturn(Optional.of(authUserInfo));
    }

    private void assertAuthorisationCodeGeneratedAndSaved(String expectedEmail) {
        verify(orchAuthCodeService, times(1))
                .generateAndSaveAuthorisationCode(
                        eq(CLIENT_ID.getValue()),
                        eq(CLIENT_SESSION_ID),
                        eq(expectedEmail),
                        anyLong());
    }

    private void assertNoAuthorisationCodeGeneratedAndSaved() {
        verify(orchAuthCodeService, times(0))
                .generateAndSaveAuthorisationCode(anyString(), anyString(), anyString(), anyLong());
    }
}
