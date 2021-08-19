package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.entity.ClientSession;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.entity.Session;
import uk.gov.di.entity.SessionState;
import uk.gov.di.exceptions.ClientNotFoundException;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.AuthorisationCodeService;
import uk.gov.di.services.AuthorizationService;
import uk.gov.di.services.ClientSessionService;
import uk.gov.di.services.SessionService;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.entity.UpdateProfileType.*;
import static uk.gov.di.helpers.CookieHelper.buildCookieString;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class UpdateProfileHandlerTest {

    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String PHONE_NUMBER = "01234567891";
    private static final boolean UPDATED_TERMS_AND_CONDITIONS_VALUE = true;
    private static final boolean CONSENT_VALUE = true;
    private static final String SESSION_ID = "a-session-id";
    private static final String CLIENT_SESSION_ID = "client-session-id";
    private static final String COOKIE = "Cookie";
    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private final Context context = mock(Context.class);
    private UpdateProfileHandler handler;
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final AuthorizationService authorizationService = mock(AuthorizationService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuthorisationCodeService authorisationCodeService =
            mock(AuthorisationCodeService.class);

    private final String TERMS_AND_CONDITIONS_VERSION =
            configurationService.getTermsAndConditionsVersion();
    private final Session session =
            new Session(SESSION_ID)
                    .setEmailAddress(TEST_EMAIL_ADDRESS)
                    .setState(SessionState.TWO_FACTOR_REQUIRED);

    @BeforeEach
    public void setUp() {
        handler =
                new UpdateProfileHandler(
                        authenticationService,
                        sessionService,
                        clientSessionService,
                        configurationService);
    }

    @Test
    public void shouldReturn200WhenUpdatingPhoneNumber() {
        when(authenticationService.userExists(eq("joe.bloggs@test.com"))).thenReturn(false);
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"updateProfileType\": \"%s\", \"profileInformation\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, ADD_PHONE_NUMBER, PHONE_NUMBER));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(authenticationService).updatePhoneNumber(eq(TEST_EMAIL_ADDRESS), eq(PHONE_NUMBER));

        assertThat(result, hasStatus(200));
    }

    @Test
    public void shouldReturn200WhenUpdatingTermsAndConditions() {
        when(authenticationService.userExists(eq(TEST_EMAIL_ADDRESS))).thenReturn(false);
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"updateProfileType\": \"%s\", \"profileInformation\": \"%s\" }",
                        TEST_EMAIL_ADDRESS,
                        UPDATE_TERMS_CONDS,
                        UPDATED_TERMS_AND_CONDITIONS_VALUE));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(authenticationService)
                .updateTermsAndConditions(eq(TEST_EMAIL_ADDRESS), eq(TERMS_AND_CONDITIONS_VERSION));

        assertThat(result, hasStatus(200));
    }

    @Test
    public void shouldReturn200WhenUpdatingProfileWithConsent() throws ClientNotFoundException {
        when(authenticationService.userExists(eq(TEST_EMAIL_ADDRESS))).thenReturn(false);
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        ClientID clientID = new ClientID();
        AuthorizationCode authorizationCode = new AuthorizationCode();
        AuthenticationRequest authRequest = generateValidClientSessionAndAuthRequest(clientID);
        var consentMap =
                Map.of(authRequest.getClientID().getValue(), List.of(String.valueOf(true)));

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
        when(authorisationCodeService.generateAuthorisationCode(
                        eq(CLIENT_SESSION_ID), eq(TEST_EMAIL_ADDRESS)))
                .thenReturn(authorizationCode);
        when(authorizationService.generateSuccessfulAuthResponse(
                        any(AuthenticationRequest.class), any(AuthorizationCode.class)))
                .thenReturn(authSuccessResponse);

        event.setHeaders(Map.of(COOKIE, buildCookieString(CLIENT_SESSION_ID)));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"updateProfileType\": \"%s\", \"profileInformation\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, CAPTURE_CONSENT, CONSENT_VALUE));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(authenticationService).updateConsent(eq(TEST_EMAIL_ADDRESS), eq(consentMap));

        assertThat(result, hasStatus(200));
    }

    @Test
    public void shouldReturn400WhenRequestIsMissingParameters() {
        when(authenticationService.userExists(eq("joe.bloggs@test.com"))).thenReturn(false);
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"updateProfileType\": \"%s\"}",
                        TEST_EMAIL_ADDRESS, ADD_PHONE_NUMBER));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(authenticationService, never())
                .updatePhoneNumber(eq(TEST_EMAIL_ADDRESS), eq(PHONE_NUMBER));

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    public void shouldReturn400IfUserTransitionsFromWrongState() {
        session.setState(SessionState.NEW);

        when(authenticationService.userExists(eq("joe.bloggs@test.com"))).thenReturn(false);
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"updateProfileType\": \"%s\", \"profileInformation\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, ADD_PHONE_NUMBER, PHONE_NUMBER));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1017));
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
    }

    private AuthenticationRequest generateValidClientSessionAndAuthRequest(ClientID clientID) {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        State state = new State();
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(responseType, scope, clientID, REDIRECT_URI)
                        .state(state)
                        .nonce(new Nonce())
                        .build();
        ClientSession clientSession =
                new ClientSession(authRequest.toParameters(), LocalDateTime.now());
        when(clientSessionService.getClientSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(clientSession));
        return authRequest;
    }
}
