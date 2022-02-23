package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.AuthorizationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.UPDATE_PROFILE_CONSENT_UPDATED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.UPDATE_PROFILE_PHONE_NUMBER;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.UPDATE_PROFILE_REQUEST_ERROR;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.UPDATE_PROFILE_REQUEST_RECEIVED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.UPDATE_PROFILE_TERMS_CONDS_ACCEPTANCE;
import static uk.gov.di.authentication.frontendapi.entity.UpdateProfileType.ADD_PHONE_NUMBER;
import static uk.gov.di.authentication.frontendapi.entity.UpdateProfileType.CAPTURE_CONSENT;
import static uk.gov.di.authentication.frontendapi.entity.UpdateProfileType.UPDATE_TERMS_CONDS;
import static uk.gov.di.authentication.shared.helpers.CookieHelper.buildCookieString;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class UpdateProfileHandlerTest {

    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String PHONE_NUMBER = "01234567891";
    private static final boolean UPDATED_TERMS_AND_CONDITIONS_VALUE = true;
    private static final boolean CONSENT_VALUE = true;
    private static final String SESSION_ID = "a-session-id";
    private static final String CLIENT_SESSION_ID = "client-session-id";
    private static final String CLIENT_ID = "client-id";
    private static final String INTERNAL_SUBJECT = new Subject().getValue();
    private static final Scope SCOPES =
            new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.OFFLINE_ACCESS);
    private static final String COOKIE = "Cookie";
    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private final Context context = mock(Context.class);
    private UpdateProfileHandler handler;
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final AuthorizationService authorizationService = mock(AuthorizationService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final ClientRegistry clientRegistry = mock(ClientRegistry.class);
    private final ClientService clientService = mock(ClientService.class);
    private final AuditService auditService = mock(AuditService.class);

    private final String TERMS_AND_CONDITIONS_VERSION =
            configurationService.getTermsAndConditionsVersion();
    private final Session session = new Session(SESSION_ID).setEmailAddress(TEST_EMAIL_ADDRESS);

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(UpdateProfileHandler.class);

    @AfterEach
    void tearDown() {
        assertThat(
                logging.events(),
                not(
                        hasItem(
                                withMessageContaining(
                                        SESSION_ID,
                                        CLIENT_SESSION_ID,
                                        CLIENT_ID,
                                        TEST_EMAIL_ADDRESS))));
        verifyNoMoreInteractions(auditService);
    }

    @BeforeEach
    void setUp() {
        when(context.getAwsRequestId()).thenReturn("request-id");
        handler =
                new UpdateProfileHandler(
                        authenticationService,
                        sessionService,
                        clientSessionService,
                        configurationService,
                        auditService,
                        clientService);
    }

    @Test
    void shouldReturn204WhenUpdatingPhoneNumber() {
        usingValidSession();
        String persistentId = "some-persistent-id-value";
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, persistentId);
        headers.put("Session-Id", session.getSessionId());
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(headers);
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"updateProfileType\": \"%s\", \"profileInformation\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, ADD_PHONE_NUMBER, PHONE_NUMBER));
        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);

        verify(authenticationService).updatePhoneNumber(eq(TEST_EMAIL_ADDRESS), eq(PHONE_NUMBER));

        assertThat(result, hasStatus(204));

        verify(auditService)
                .submitAuditEvent(
                        UPDATE_PROFILE_PHONE_NUMBER,
                        "request-id",
                        session.getSessionId(),
                        "",
                        "",
                        TEST_EMAIL_ADDRESS,
                        "",
                        PHONE_NUMBER,
                        persistentId);
    }

    @Test
    void shouldReturn204WhenUpdatingTermsAndConditions() {
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"updateProfileType\": \"%s\", \"profileInformation\": \"%s\" }",
                        TEST_EMAIL_ADDRESS,
                        UPDATE_TERMS_CONDS,
                        UPDATED_TERMS_AND_CONDITIONS_VALUE));
        when(authenticationService.getUserProfileFromEmail(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.of(generateUserProfileWithConsent()));
        when(clientService.getClient(CLIENT_ID)).thenReturn(Optional.of(clientRegistry));
        when(clientRegistry.getClientID()).thenReturn(CLIENT_ID);
        generateValidClientSessionAndAuthRequest(new ClientID(CLIENT_ID));

        generateValidClientSessionAndAuthRequest(new ClientID(CLIENT_ID));
        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);

        verify(authenticationService)
                .updateTermsAndConditions(eq(TEST_EMAIL_ADDRESS), eq(TERMS_AND_CONDITIONS_VERSION));

        assertThat(result, hasStatus(204));

        verify(auditService)
                .submitAuditEvent(
                        UPDATE_PROFILE_TERMS_CONDS_ACCEPTANCE,
                        "request-id",
                        session.getSessionId(),
                        CLIENT_ID,
                        INTERNAL_SUBJECT,
                        TEST_EMAIL_ADDRESS,
                        "",
                        PHONE_NUMBER,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE);
    }

    @Test
    void shouldReturn204WhenUpdatingProfileWithConsent()
            throws ClientNotFoundException, URISyntaxException {
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        ClientID clientID = new ClientID();
        AuthorizationCode authorizationCode = new AuthorizationCode();
        AuthenticationRequest authRequest = generateValidClientSessionAndAuthRequest(clientID);

        AuthenticationSuccessResponse authSuccessResponse =
                new AuthenticationSuccessResponse(
                        authRequest.getRedirectionURI(),
                        authorizationCode,
                        null,
                        null,
                        authRequest.getState(),
                        null,
                        null);
        when(authenticationService.getUserProfileFromEmail(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.of(generateUserProfileWithoutConsent()));
        when(authorizationService.isClientRedirectUriValid(eq(clientID), eq(REDIRECT_URI)))
                .thenReturn(true);
        when(authorizationService.generateSuccessfulAuthResponse(
                        any(AuthenticationRequest.class), any(AuthorizationCode.class)))
                .thenReturn(authSuccessResponse);

        event.setHeaders(
                Map.of(
                        COOKIE,
                        buildCookieString(
                                "gs",
                                SESSION_ID + "." + CLIENT_SESSION_ID,
                                3600,
                                "Secure; HttpOnly;",
                                "domain")));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"updateProfileType\": \"%s\", \"profileInformation\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, CAPTURE_CONSENT, CONSENT_VALUE));

        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);

        verify(authenticationService)
                .updateConsent(eq(TEST_EMAIL_ADDRESS), any(ClientConsent.class));

        assertThat(result, hasStatus(204));

        verify(auditService)
                .submitAuditEvent(
                        UPDATE_PROFILE_CONSENT_UPDATED,
                        "request-id",
                        session.getSessionId(),
                        clientID.getValue(),
                        INTERNAL_SUBJECT,
                        TEST_EMAIL_ADDRESS,
                        "",
                        PHONE_NUMBER,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE);
    }

    @Test
    void shouldReturn400WhenRequestIsMissingParameters() {
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"updateProfileType\": \"%s\"}",
                        TEST_EMAIL_ADDRESS, ADD_PHONE_NUMBER));
        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);

        verify(authenticationService, never())
                .updatePhoneNumber(eq(TEST_EMAIL_ADDRESS), eq(PHONE_NUMBER));

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));

        verify(auditService)
                .submitAuditEvent(
                        UPDATE_PROFILE_REQUEST_ERROR, "request-id", "", "", "", "", "", "", "");
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
    }

    private AuthenticationRequest generateValidClientSessionAndAuthRequest(ClientID clientID) {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        State state = new State();
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(responseType, SCOPES, clientID, REDIRECT_URI)
                        .state(state)
                        .nonce(new Nonce())
                        .build();
        ClientSession clientSession =
                new ClientSession(
                        authRequest.toParameters(), LocalDateTime.now(), mock(VectorOfTrust.class));
        when(clientSessionService.getClientSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(clientSession));
        return authRequest;
    }

    private APIGatewayProxyResponseEvent makeHandlerRequest(APIGatewayProxyRequestEvent event) {
        var response = handler.handleRequest(event, context);

        verify(auditService)
                .submitAuditEvent(
                        UPDATE_PROFILE_REQUEST_RECEIVED, "request-id", "", "", "", "", "", "", "");

        return response;
    }

    private UserProfile generateUserProfileWithoutConsent() {
        return new UserProfile()
                .setEmail(TEST_EMAIL_ADDRESS)
                .setEmailVerified(true)
                .setPhoneNumber(PHONE_NUMBER)
                .setEmailVerified(true)
                .setPublicSubjectID(new Subject().getValue())
                .setSubjectID(INTERNAL_SUBJECT);
    }

    private UserProfile generateUserProfileWithConsent() {
        Set<String> claims = ValidScopes.getClaimsForListOfScopes(SCOPES.toStringList());
        return new UserProfile()
                .setEmail(TEST_EMAIL_ADDRESS)
                .setEmailVerified(true)
                .setPhoneNumber(PHONE_NUMBER)
                .setEmailVerified(true)
                .setPublicSubjectID(new Subject().getValue())
                .setSubjectID(INTERNAL_SUBJECT)
                .setClientConsent(
                        new ClientConsent(
                                CLIENT_ID, claims, LocalDateTime.now(ZoneId.of("UTC")).toString()));
    }
}
