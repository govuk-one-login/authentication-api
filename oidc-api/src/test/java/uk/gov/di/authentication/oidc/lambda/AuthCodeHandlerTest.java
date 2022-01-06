package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
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
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthorisationCodeService;
import uk.gov.di.authentication.shared.services.AuthorizationService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;
import static uk.gov.di.authentication.shared.entity.Session.AccountState.NEW;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthCodeHandlerTest {
    private static final String SESSION_ID = IdGenerator.generate();
    private static final String CLIENT_SESSION_ID = IdGenerator.generate();
    private static final String PERSISTENT_SESSION_ID = IdGenerator.generate();
    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private static final ClientID CLIENT_ID = new ClientID();
    private final AuthorizationService authorizationService = mock(AuthorizationService.class);
    private final AuthorisationCodeService authorisationCodeService =
            mock(AuthorisationCodeService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final Context context = mock(Context.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ClientSession clientSession = mock(ClientSession.class);
    private final AuditService auditService = mock(AuditService.class);
    private final VectorOfTrust vectorOfTrust = mock(VectorOfTrust.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private AuthCodeHandler handler;

    private final Session session =
            new Session(SESSION_ID)
                    .addClientSession(CLIENT_SESSION_ID)
                    .setEmailAddress(EMAIL)
                    .setCurrentCredentialStrength(MEDIUM_LEVEL);

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
                        sessionService,
                        authorisationCodeService,
                        authorizationService,
                        clientSessionService,
                        auditService,
                        cloudwatchMetricsService,
                        configurationService);
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
        when(configurationService.getEnvironment()).thenReturn("unit-test");
    }

    private static Stream<Arguments> upliftTestParameters() {
        return Stream.of(
                arguments(null, LOW_LEVEL, LOW_LEVEL),
                arguments(LOW_LEVEL, LOW_LEVEL, LOW_LEVEL),
                arguments(MEDIUM_LEVEL, MEDIUM_LEVEL, MEDIUM_LEVEL),
                arguments(LOW_LEVEL, MEDIUM_LEVEL, MEDIUM_LEVEL),
                arguments(MEDIUM_LEVEL, LOW_LEVEL, MEDIUM_LEVEL));
    }

    @ParameterizedTest
    @MethodSource("upliftTestParameters")
    void shouldGenerateSuccessfulAuthResponseAndUpliftAsNecessary(
            CredentialTrustLevel initialLevel,
            CredentialTrustLevel requestedLevel,
            CredentialTrustLevel finalLevel)
            throws ClientNotFoundException, URISyntaxException, JsonProcessingException {
        AuthorizationCode authorizationCode = new AuthorizationCode();
        AuthenticationRequest authRequest = generateValidSessionAndAuthRequest(requestedLevel);
        session.setCurrentCredentialStrength(initialLevel).setNewAccount(NEW);
        AuthenticationSuccessResponse authSuccessResponse =
                new AuthenticationSuccessResponse(
                        authRequest.getRedirectionURI(),
                        authorizationCode,
                        null,
                        null,
                        authRequest.getState(),
                        null,
                        authRequest.getResponseMode());

        when(authorizationService.isClientRedirectUriValid(eq(CLIENT_ID), eq(REDIRECT_URI)))
                .thenReturn(true);
        when(authorisationCodeService.generateAuthorisationCode(eq(CLIENT_SESSION_ID), eq(EMAIL)))
                .thenReturn(authorizationCode);
        when(authorizationService.isClientCookieConsentShared(CLIENT_ID)).thenReturn(false);
        when(authorizationService.generateSuccessfulAuthResponse(
                        any(AuthenticationRequest.class), any(AuthorizationCode.class)))
                .thenReturn(authSuccessResponse);

        APIGatewayProxyResponseEvent response = generateApiRequest();

        assertThat(response, hasStatus(200));
        AuthCodeResponse authCodeResponse =
                new ObjectMapper().readValue(response.getBody(), AuthCodeResponse.class);
        assertThat(authCodeResponse.getLocation(), equalTo(authSuccessResponse.toURI().toString()));
        assertFalse(authCodeResponse.getCookieConsentShared());

        assertThat(session.getCurrentCredentialStrength(), equalTo(finalLevel));

        verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.AUTH_CODE_ISSUED,
                        "aws-session-id",
                        SESSION_ID,
                        CLIENT_ID.getValue(),
                        AuditService.UNKNOWN,
                        EMAIL,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_SESSION_ID);

        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "SignIn",
                        Map.of(
                                "Account",
                                "NEW",
                                "Environment",
                                "unit-test",
                                "Client",
                                CLIENT_ID.getValue()));
    }

    @Test
    void shouldGenerateErrorResponseWhenSessionIsNotFound() {
        APIGatewayProxyResponseEvent response = generateApiRequest();

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1000));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldGenerateErrorResponseWhenRedirectUriIsInvalid() throws ClientNotFoundException {
        generateValidSessionAndAuthRequest(MEDIUM_LEVEL);
        when(authorizationService.isClientRedirectUriValid(eq(CLIENT_ID), eq(REDIRECT_URI)))
                .thenReturn(false);
        APIGatewayProxyResponseEvent response = generateApiRequest();

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1016));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldGenerateErrorResponseWhenClientIsNotFound()
            throws ClientNotFoundException, JsonProcessingException {
        AuthenticationErrorResponse authenticationErrorResponse =
                new AuthenticationErrorResponse(
                        REDIRECT_URI, OAuth2Error.INVALID_CLIENT, null, null);
        when(authorizationService.generateAuthenticationErrorResponse(
                        any(AuthenticationRequest.class), eq(OAuth2Error.INVALID_CLIENT)))
                .thenReturn(authenticationErrorResponse);
        generateValidSessionAndAuthRequest(MEDIUM_LEVEL);
        doThrow(ClientNotFoundException.class)
                .when(authorizationService)
                .isClientRedirectUriValid(eq(CLIENT_ID), eq(REDIRECT_URI));

        APIGatewayProxyResponseEvent response = generateApiRequest();

        assertThat(response, hasStatus(200));
        AuthCodeResponse authCodeResponse =
                new ObjectMapper().readValue(response.getBody(), AuthCodeResponse.class);
        assertThat(
                authCodeResponse.getLocation(),
                equalTo(
                        "http://localhost/redirect?error=invalid_client&error_description=Client+authentication+failed"));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldGenerateErrorResponseIfUnableToParseAuthRequest() throws JsonProcessingException {
        AuthenticationErrorResponse authenticationErrorResponse =
                new AuthenticationErrorResponse(
                        REDIRECT_URI, OAuth2Error.INVALID_REQUEST, null, null);
        when(authorizationService.generateAuthenticationErrorResponse(
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

        assertThat(response, hasStatus(200));
        AuthCodeResponse authCodeResponse =
                new ObjectMapper().readValue(response.getBody(), AuthCodeResponse.class);
        assertThat(
                authCodeResponse.getLocation(),
                equalTo(
                        "http://localhost/redirect?error=invalid_request&error_description=Invalid+request"));

        verifyNoInteractions(auditService);
    }

    @Test
    public void shouldReturn400IfSessionIdMissing() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1000));

        verifyNoInteractions(auditService);
    }

    @Test
    public void shouldReturn400IfClientSessionIdMissing() {
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
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1018));

        verifyNoInteractions(auditService);
    }

    private AuthenticationRequest generateValidSessionAndAuthRequest(
            CredentialTrustLevel requestedLevel) {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        Nonce nonce = new Nonce();
        scope.add(OIDCScopeValue.OPENID);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(responseType, scope, CLIENT_ID, REDIRECT_URI)
                        .state(new State())
                        .nonce(nonce)
                        .build();
        generateValidSession(authRequest.toParameters(), requestedLevel);
        return authRequest;
    }

    private void generateValidSession(
            Map<String, List<String>> authRequest, CredentialTrustLevel requestedLevel) {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
        when(clientSessionService.getClientSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(clientSession));
        when(vectorOfTrust.getCredentialTrustLevel()).thenReturn(requestedLevel);
        when(clientSession.getEffectiveVectorOfTrust()).thenReturn(vectorOfTrust);
        when(clientSession.getAuthRequestParams()).thenReturn(authRequest);
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
}
