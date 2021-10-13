package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
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
import org.apache.http.client.utils.URIBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.oidc.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.services.AuthorisationCodeService;
import uk.gov.di.authentication.shared.services.AuthorizationService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.oidc.entity.RequestParameters.COOKIE_CONSENT;
import static uk.gov.di.authentication.oidc.lambda.AuthCodeHandler.COOKIE_CONSENT_ACCEPT;
import static uk.gov.di.authentication.oidc.lambda.AuthCodeHandler.COOKIE_CONSENT_NOT_ENGAGED;
import static uk.gov.di.authentication.oidc.lambda.AuthCodeHandler.COOKIE_CONSENT_PARAM_NAME;
import static uk.gov.di.authentication.oidc.lambda.AuthCodeHandler.COOKIE_CONSENT_REJECT;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthCodeHandlerTest {
    private static final String SESSION_ID = "a-session-id";
    private static final String CLIENT_SESSION_ID = "client-session-id";
    private static final String COOKIE = "Cookie";
    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private final AuthorizationService authorizationService = mock(AuthorizationService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuthorisationCodeService authorisationCodeService =
            mock(AuthorisationCodeService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final Context context = mock(Context.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ClientSession clientSession = mock(ClientSession.class);
    private final VectorOfTrust vectorOfTrust = mock(VectorOfTrust.class);
    private AuthCodeHandler handler;

    private final Session session =
            new Session(SESSION_ID)
                    .addClientSession(CLIENT_SESSION_ID)
                    .setEmailAddress(EMAIL)
                    .setState(SessionState.MFA_CODE_VERIFIED)
                    .setCurrentCredentialStrength(MEDIUM_LEVEL);

    @BeforeEach
    public void setUp() {
        handler =
                new AuthCodeHandler(
                        sessionService,
                        authorisationCodeService,
                        configurationService,
                        authorizationService,
                        clientSessionService);
    }

    private static Stream<Arguments> upliftTestParameters() {
        return Stream.of(
                arguments(null, LOW_LEVEL, LOW_LEVEL),
                arguments(LOW_LEVEL, LOW_LEVEL, LOW_LEVEL),
                arguments(MEDIUM_LEVEL, MEDIUM_LEVEL, MEDIUM_LEVEL),
                arguments(LOW_LEVEL, MEDIUM_LEVEL, MEDIUM_LEVEL),
                arguments(MEDIUM_LEVEL, LOW_LEVEL, MEDIUM_LEVEL));
    }

    private static Stream<Arguments> cookieConsentTestParameters() {
        return Stream.of(
                arguments("", Boolean.TRUE, COOKIE_CONSENT_NOT_ENGAGED),
                arguments(COOKIE_CONSENT_NOT_ENGAGED, Boolean.TRUE, COOKIE_CONSENT_NOT_ENGAGED),
                arguments(COOKIE_CONSENT_ACCEPT, Boolean.TRUE, COOKIE_CONSENT_ACCEPT),
                arguments(COOKIE_CONSENT_REJECT, Boolean.TRUE, COOKIE_CONSENT_REJECT));
    }

    @ParameterizedTest
    @MethodSource("upliftTestParameters")
    public void shouldGenerateSuccessfulAuthResponseAndUpliftAsNecessary(
            CredentialTrustLevel initialLevel,
            CredentialTrustLevel requestedLevel,
            CredentialTrustLevel finalLevel)
            throws ClientNotFoundException {
        ClientID clientID = new ClientID();
        AuthorizationCode authorizationCode = new AuthorizationCode();
        AuthenticationRequest authRequest =
                generateValidSessionAndAuthRequest(clientID, new State(), requestedLevel);
        session.setCurrentCredentialStrength(initialLevel);
        AuthenticationSuccessResponse authSuccessResponse =
                new AuthenticationSuccessResponse(
                        authRequest.getRedirectionURI(),
                        authorizationCode,
                        null,
                        null,
                        authRequest.getState(),
                        null,
                        authRequest.getResponseMode());

        when(authorizationService.isClientRedirectUriValid(eq(clientID), eq(REDIRECT_URI)))
                .thenReturn(true);
        when(authorisationCodeService.generateAuthorisationCode(eq(CLIENT_SESSION_ID), eq(EMAIL)))
                .thenReturn(authorizationCode);
        when(authorizationService.generateSuccessfulAuthResponse(
                        any(AuthenticationRequest.class), any(AuthorizationCode.class)))
                .thenReturn(authSuccessResponse);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(authSuccessResponse.toURI().toString()));

        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                not(containsString(COOKIE_CONSENT_PARAM_NAME)));

        assertThat(session.getCurrentCredentialStrength(), equalTo(finalLevel));
    }

    @ParameterizedTest
    @MethodSource("cookieConsentTestParameters")
    public void shouldGenerateSuccessfulAuthResponseWithConsentParams(
            String cookieValue,
            boolean clientRegistryCookieConsentValue,
            String returnedCookieConsentParamValue)
            throws ClientNotFoundException, URISyntaxException {
        ClientID clientID = new ClientID();
        AuthorizationCode authorizationCode = new AuthorizationCode();
        AuthenticationRequest authRequest =
                generateValidSessionAndAuthRequest(clientID, new State(), MEDIUM_LEVEL);
        session.setCurrentCredentialStrength(MEDIUM_LEVEL);
        AuthenticationSuccessResponse authSuccessResponse =
                generateSuccessfulAuthResponse(
                        authRequest,
                        authorizationCode,
                        COOKIE_CONSENT_PARAM_NAME,
                        returnedCookieConsentParamValue);

        when(authorizationService.isClientRedirectUriValid(eq(clientID), eq(REDIRECT_URI)))
                .thenReturn(true);
        when(authorizationService.isClientCookieConsentShared(eq(clientID)))
                .thenReturn(clientRegistryCookieConsentValue);
        when(authorisationCodeService.generateAuthorisationCode(eq(CLIENT_SESSION_ID), eq(EMAIL)))
                .thenReturn(authorizationCode);
        when(authorizationService.generateSuccessfulAuthResponse(
                        any(AuthenticationRequest.class),
                        any(AuthorizationCode.class),
                        any(String.class),
                        any(String.class)))
                .thenCallRealMethod();

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        event.setQueryStringParameters(Map.of(COOKIE_CONSENT, cookieValue));
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                equalTo(authSuccessResponse.toURI().toString()));

        assertThat(
                response.getHeaders().get(ResponseHeaders.LOCATION),
                containsString(COOKIE_CONSENT_PARAM_NAME + "=" + returnedCookieConsentParamValue));

        assertThat(session.getCurrentCredentialStrength(), equalTo(MEDIUM_LEVEL));
    }

    @Test
    public void shouldGenerateErrorResponseWhenSessionIsNotFound() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1000));
    }

    @Test
    public void shouldGenerateErrorResponseWhenRedirectUriIsInvalid()
            throws ClientNotFoundException {
        ClientID clientID = new ClientID();
        generateValidSessionAndAuthRequest(clientID, new State(), MEDIUM_LEVEL);
        when(authorizationService.isClientRedirectUriValid(eq(new ClientID()), eq(REDIRECT_URI)))
                .thenReturn(false);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1016));
    }

    @Test
    public void shouldGenerateErrorResponseWhenClientIsNotFound() throws ClientNotFoundException {
        State state = new State();
        AuthenticationErrorResponse authenticationErrorResponse =
                new AuthenticationErrorResponse(
                        REDIRECT_URI, OAuth2Error.INVALID_CLIENT, null, null);
        when(authorizationService.generateAuthenticationErrorResponse(
                        any(AuthenticationRequest.class), eq(OAuth2Error.INVALID_CLIENT)))
                .thenReturn(authenticationErrorResponse);
        ClientID clientID = new ClientID();
        generateValidSessionAndAuthRequest(clientID, state, MEDIUM_LEVEL);
        doThrow(ClientNotFoundException.class)
                .when(authorizationService)
                .isClientRedirectUriValid(eq(clientID), eq(REDIRECT_URI));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(302));
        assertEquals(
                "http://localhost/redirect?error=invalid_client&error_description=Client+authentication+failed",
                response.getHeaders().get(ResponseHeaders.LOCATION));
    }

    @Test
    public void shouldGenerateErrorResponseIfUnableToParseAuthRequest() {
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
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(302));
        assertEquals(
                "http://localhost/redirect?error=invalid_request&error_description=Invalid+request",
                response.getHeaders().get(ResponseHeaders.LOCATION));
    }

    @Test
    public void shouldReturn400IfUserTransitionsFromWrongState() throws ClientNotFoundException {
        session.setState(SessionState.NEW);

        ClientID clientID = new ClientID();
        AuthorizationCode authorizationCode = new AuthorizationCode();
        AuthenticationRequest authRequest =
                generateValidSessionAndAuthRequest(clientID, new State(), MEDIUM_LEVEL);
        AuthenticationSuccessResponse authSuccessResponse =
                new AuthenticationSuccessResponse(
                        authRequest.getRedirectionURI(),
                        authorizationCode,
                        null,
                        null,
                        authRequest.getState(),
                        null,
                        null);

        when(authorizationService.isClientRedirectUriValid(eq(clientID), eq(REDIRECT_URI)))
                .thenReturn(true);
        when(authorisationCodeService.generateAuthorisationCode(eq(CLIENT_SESSION_ID), eq(EMAIL)))
                .thenReturn(authorizationCode);
        when(authorizationService.generateSuccessfulAuthResponse(
                        any(AuthenticationRequest.class), any(AuthorizationCode.class)))
                .thenReturn(authSuccessResponse);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1017));
    }

    private AuthenticationRequest generateValidSessionAndAuthRequest(
            ClientID clientID, State state, CredentialTrustLevel requestedLevel) {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        Nonce nonce = new Nonce();
        scope.add(OIDCScopeValue.OPENID);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(responseType, scope, clientID, REDIRECT_URI)
                        .state(state)
                        .nonce(nonce)
                        .build();
        generateValidSession(authRequest.toParameters(), requestedLevel);
        return authRequest;
    }

    private void generateValidSession(
            Map<String, List<String>> authRequest, CredentialTrustLevel requestedLevel) {
        when(sessionService.readSessionFromRedis(SESSION_ID)).thenReturn(Optional.of(session));
        when(vectorOfTrust.getCredentialTrustLevel()).thenReturn(requestedLevel);
        when(clientSession.getEffectiveVectorOfTrust()).thenReturn(vectorOfTrust);
        when(clientSession.getAuthRequestParams()).thenReturn(authRequest);
        when(clientSessionService.getClientSession(eq(CLIENT_SESSION_ID)))
                .thenReturn(clientSession);
    }

    public AuthenticationSuccessResponse generateSuccessfulAuthResponse(
            AuthenticationRequest authRequest,
            AuthorizationCode authorizationCode,
            String additionalParamName,
            String additionalParamValue)
            throws URISyntaxException {
        return new AuthenticationSuccessResponse(
                new URIBuilder(authRequest.getRedirectionURI())
                        .addParameter(additionalParamName, additionalParamValue)
                        .build(),
                authorizationCode,
                null,
                null,
                authRequest.getState(),
                null,
                authRequest.getResponseMode());
    }

    private static String buildCookieString() {
        return format(
                "%s=%s.%s; Max-Age=%d; %s",
                "gs", SESSION_ID, CLIENT_SESSION_ID, 3600, "Secure; HttpOnly;");
    }
}
