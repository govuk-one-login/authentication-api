package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.OAuth2Error;
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
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.CustomScopeValue;
import uk.gov.di.orchestration.shared.entity.ErrorResponse;
import uk.gov.di.orchestration.shared.entity.MFAMethodType;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.entity.UserProfile;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.ClientNotFoundException;
import uk.gov.di.orchestration.shared.exceptions.UserNotFoundException;
import uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.helpers.PersistentIdHelper;
import uk.gov.di.orchestration.shared.helpers.SaltHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.AuthCodeResponseGenerationService;
import uk.gov.di.orchestration.shared.services.AuthorisationCodeService;
import uk.gov.di.orchestration.shared.services.ClientSessionService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.DynamoService;
import uk.gov.di.orchestration.shared.services.OrchSessionService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.SessionService;
import uk.gov.di.orchestration.sharedtest.helper.KeyPairHelper;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
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
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.oidc.helper.RequestObjectTestHelper.generateSignedJWT;
import static uk.gov.di.orchestration.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.orchestration.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;
import static uk.gov.di.orchestration.shared.entity.Session.AccountState;
import static uk.gov.di.orchestration.shared.entity.Session.AccountState.EXISTING;
import static uk.gov.di.orchestration.shared.entity.Session.AccountState.EXISTING_DOC_APP_JOURNEY;
import static uk.gov.di.orchestration.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.orchestration.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthCodeHandlerTest {
    private final AuthCodeResponseGenerationService authCodeResponseService =
            mock(AuthCodeResponseGenerationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final AuthorisationCodeService authorisationCodeService =
            mock(AuthorisationCodeService.class);
    private final ClientSession clientSession = mock(ClientSession.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final Context context = mock(Context.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final OrchestrationAuthorizationService orchestrationAuthorizationService =
            mock(OrchestrationAuthorizationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final OrchSessionService orchSessionService = mock(OrchSessionService.class);
    private final VectorOfTrust vectorOfTrust = mock(VectorOfTrust.class);

    private static final String SESSION_ID = IdGenerator.generate();
    private static final String CLIENT_SESSION_ID = IdGenerator.generate();
    private static final String PERSISTENT_SESSION_ID = IdGenerator.generate();
    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final Subject SUBJECT = new Subject();
    private static final String DOC_APP_SUBJECT_ID = "docAppSubjectId";
    private static final ClientID CLIENT_ID = new ClientID();
    private static final String CLIENT_NAME = "test-client-name";
    private static final String AUDIENCE = "oidc-audience";
    private static final State STATE = new State();
    private static final Nonce NONCE = new Nonce();
    private static final byte[] SALT = SaltHelper.generateNewSalt();
    private static final Json objectMapper = SerializationService.getInstance();
    private AuthCodeHandler handler;

    private final Session session = new Session(SESSION_ID).addClientSession(CLIENT_SESSION_ID);
    private final OrchSessionItem orchSession = new OrchSessionItem(SESSION_ID);

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
    void setUp() throws UserNotFoundException, ClientNotFoundException {
        handler =
                new AuthCodeHandler(
                        sessionService,
                        orchSessionService,
                        authCodeResponseService,
                        authorisationCodeService,
                        orchestrationAuthorizationService,
                        clientSessionService,
                        auditService,
                        cloudwatchMetricsService,
                        configurationService,
                        dynamoService,
                        dynamoClientService);
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
        when(configurationService.getEnvironment()).thenReturn("unit-test");
        when(configurationService.getInternalSectorURI()).thenReturn(INTERNAL_SECTOR_URI);
        when(authCodeResponseService.getSubjectId(session)).thenReturn(SUBJECT.getValue());
        when(authCodeResponseService.getRpPairwiseId(session, CLIENT_ID, dynamoClientService))
                .thenReturn(
                        ClientSubjectHelper.calculatePairwiseIdentifier(
                                SUBJECT.getValue(), "rp-sector-uri", SALT));
        doAnswer(
                        (i) -> {
                            session.setNewAccount(EXISTING_DOC_APP_JOURNEY);
                            return null;
                        })
                .when(authCodeResponseService)
                .saveSession(true, sessionService, session, orchSessionService, orchSession);
        doAnswer(
                        (i) -> {
                            session.setAuthenticated(true).setNewAccount(EXISTING);
                            return null;
                        })
                .when(authCodeResponseService)
                .saveSession(false, sessionService, session, orchSessionService, orchSession);
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
            throws ClientNotFoundException, Json.JsonException, JOSEException {
        var userProfile = new UserProfile().withEmail(EMAIL).withSubjectID(SUBJECT.getValue());
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(generateClientRegistry()));
        when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(SALT);
        if (Objects.nonNull(mfaMethodType)) {
            when(authCodeResponseService.getDimensions(
                            eq(session),
                            eq(orchSession),
                            eq(clientSession),
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
                .processVectorOfTrust(eq(clientSession), any());
        var expectedCommonSubject =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), "test.account.gov.uk", SaltHelper.generateNewSalt());
        session.setInternalCommonSubjectIdentifier(expectedCommonSubject);
        var authorizationCode = new AuthorizationCode();
        var authRequest = generateValidSessionAndAuthRequest(requestedLevel, false);
        session.setCurrentCredentialStrength(initialLevel)
                .setNewAccount(AccountState.NEW)
                .setEmailAddress(EMAIL)
                .setVerifiedMfaMethodType(mfaMethodType);
        var authSuccessResponse =
                new AuthenticationSuccessResponse(
                        authRequest.getRedirectionURI(),
                        authorizationCode,
                        null,
                        null,
                        authRequest.getState(),
                        null,
                        authRequest.getResponseMode());
        when(dynamoService.getUserProfileByEmailMaybe(EMAIL)).thenReturn(Optional.of(userProfile));
        when(orchestrationAuthorizationService.isClientRedirectUriValid(CLIENT_ID, REDIRECT_URI))
                .thenReturn(true);
        when(authorisationCodeService.generateAndSaveAuthorisationCode(
                        CLIENT_SESSION_ID, EMAIL, clientSession))
                .thenReturn(authorizationCode);
        when(orchestrationAuthorizationService.generateSuccessfulAuthResponse(
                        any(AuthenticationRequest.class),
                        any(AuthorizationCode.class),
                        any(URI.class),
                        any(State.class)))
                .thenReturn(authSuccessResponse);
        when(clientSession.getVtrList()).thenReturn(List.of(new VectorOfTrust(requestedLevel)));
        when(clientSession.getVtrLocsAsCommaSeparatedString()).thenReturn("P0");

        var response = generateApiRequest();

        assertThat(response, hasStatus(200));
        var authCodeResponse = objectMapper.readValue(response.getBody(), AuthCodeResponse.class);
        assertThat(authCodeResponse.getLocation(), equalTo(authSuccessResponse.toURI().toString()));
        assertThat(session.getCurrentCredentialStrength(), equalTo(finalLevel));
        assertTrue(session.isAuthenticated());

        verify(authCodeResponseService, times(1))
                .saveSession(
                        anyBoolean(),
                        eq(sessionService),
                        eq(session),
                        eq(orchSessionService),
                        eq(orchSession));

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
                                .withUserId(expectedCommonSubject)
                                .withEmail(EMAIL)
                                .withIpAddress("123.123.123.123")
                                .withPersistentSessionId(PERSISTENT_SESSION_ID),
                        pair("internalSubjectId", SUBJECT.getValue()),
                        pair("isNewAccount", AccountState.NEW),
                        pair("rpPairwiseId", expectedRpPairwiseId),
                        pair("authCode", authorizationCode),
                        pair("nonce", NONCE.getValue()));

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
    }

    private static Stream<CredentialTrustLevel> docAppTestParameters() {
        return Stream.of(LOW_LEVEL, MEDIUM_LEVEL);
    }

    @ParameterizedTest
    @MethodSource("docAppTestParameters")
    void shouldGenerateSuccessfulAuthResponseForDocAppJourney(CredentialTrustLevel requestedLevel)
            throws Json.JsonException, ClientNotFoundException, JOSEException {
        var authorizationCode = new AuthorizationCode();
        var authRequest = generateValidSessionAndAuthRequest(requestedLevel, true);
        session.setNewAccount(AccountState.UNKNOWN);
        var authSuccessResponse =
                new AuthenticationSuccessResponse(
                        authRequest.getRedirectionURI(),
                        authorizationCode,
                        null,
                        null,
                        authRequest.getState(),
                        null,
                        authRequest.getResponseMode());

        when(clientSession.getDocAppSubjectId()).thenReturn(new Subject(DOC_APP_SUBJECT_ID));
        when(clientSession.getVtrList()).thenReturn(List.of(new VectorOfTrust(requestedLevel)));
        when(orchestrationAuthorizationService.isClientRedirectUriValid(CLIENT_ID, REDIRECT_URI))
                .thenReturn(true);
        when(authorisationCodeService.generateAndSaveAuthorisationCode(
                        CLIENT_SESSION_ID, null, clientSession))
                .thenReturn(authorizationCode);
        when(authCodeResponseService.getDimensions(
                        eq(session),
                        eq(orchSession),
                        eq(clientSession),
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
        assertThat(session.getCurrentCredentialStrength(), equalTo(requestedLevel));
        assertFalse(session.isAuthenticated());
        verify(authCodeResponseService, times(1))
                .saveSession(
                        anyBoolean(),
                        eq(sessionService),
                        eq(session),
                        any(OrchSessionService.class),
                        any(OrchSessionItem.class));
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
                        pair("isNewAccount", AccountState.UNKNOWN),
                        pair("rpPairwiseId", AuditService.UNKNOWN),
                        pair("authCode", authorizationCode),
                        pair("nonce", NONCE.getValue()));

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
    }

    @Test
    void shouldGenerateErrorResponseWhenSessionIsNotFound() {
        APIGatewayProxyResponseEvent response = generateApiRequest();

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1000));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldGenerateErrorResponseWhenOrchSessionIsNotFound() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
        when(clientSessionService.getClientSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(clientSession));
        when(clientSession.getClientName()).thenReturn(CLIENT_NAME);

        APIGatewayProxyResponseEvent response = generateApiRequest();

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1000));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldGenerateErrorResponseWhenRedirectUriIsInvalid()
            throws ClientNotFoundException, JOSEException {
        session.setEmailAddress(EMAIL);
        generateValidSessionAndAuthRequest(MEDIUM_LEVEL, false);
        when(orchestrationAuthorizationService.isClientRedirectUriValid(CLIENT_ID, REDIRECT_URI))
                .thenReturn(false);
        APIGatewayProxyResponseEvent response = generateApiRequest();

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1016));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldGenerateErrorResponseWhenClientIsNotFound()
            throws ClientNotFoundException, Json.JsonException, JOSEException {
        session.setEmailAddress(EMAIL);
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
        doThrow(ClientNotFoundException.class)
                .when(orchestrationAuthorizationService)
                .isClientRedirectUriValid(eq(CLIENT_ID), eq(REDIRECT_URI));

        APIGatewayProxyResponseEvent response = generateApiRequest();

        assertThat(response, hasStatus(500));
        AuthCodeResponse authCodeResponse =
                objectMapper.readValue(response.getBody(), AuthCodeResponse.class);
        assertThat(
                authCodeResponse.getLocation(),
                equalTo(
                        "http://localhost/redirect?error=invalid_client&error_description=Client+authentication+failed"));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldGenerateErrorResponseIfUnableToParseAuthRequest() throws Json.JsonException {
        session.setEmailAddress(EMAIL);
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
    }

    @Test
    void shouldReturn400IfSessionIdMissing() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1000));

        verifyNoInteractions(auditService);
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
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
        when(orchSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(orchSession));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1018));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldUpdateOrchSession() throws JOSEException, ClientNotFoundException {

        var authorizationCode = new AuthorizationCode();
        var authRequest = generateValidSessionAndAuthRequest(MEDIUM_LEVEL, false);

        session.setNewAccount(AccountState.UNKNOWN);
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

        when(clientSession.getDocAppSubjectId()).thenReturn(new Subject(DOC_APP_SUBJECT_ID));
        when(clientSession.getVtrList()).thenReturn(List.of(new VectorOfTrust(MEDIUM_LEVEL)));
        when(orchestrationAuthorizationService.isClientRedirectUriValid(CLIENT_ID, REDIRECT_URI))
                .thenReturn(true);
        when(authorisationCodeService.generateAndSaveAuthorisationCode(
                        CLIENT_SESSION_ID, null, clientSession))
                .thenReturn(authorizationCode);
        when(authCodeResponseService.getDimensions(
                        eq(session),
                        eq(orchSession),
                        eq(clientSession),
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
                        anyBoolean(),
                        eq(sessionService),
                        eq(session),
                        any(OrchSessionService.class),
                        any(OrchSessionItem.class));
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
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
        when(orchSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(orchSession));
        when(clientSessionService.getClientSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(clientSession));
        when(vectorOfTrust.getCredentialTrustLevel()).thenReturn(requestedLevel);
        when(clientSession.getAuthRequestParams()).thenReturn(authRequestParams);
        when(clientSession.getClientName()).thenReturn(CLIENT_NAME);
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
        var keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
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

    private ClientRegistry generateClientRegistry() {
        return new ClientRegistry()
                .withRedirectUrls(singletonList(REDIRECT_URI.toString()))
                .withClientID(CLIENT_ID.getValue())
                .withSectorIdentifierUri("https://rp-sector-uri")
                .withContacts(singletonList("joe.bloggs@digital.cabinet-office.gov.uk"))
                .withTestClient(false)
                .withScopes(singletonList("openid"));
    }
}
