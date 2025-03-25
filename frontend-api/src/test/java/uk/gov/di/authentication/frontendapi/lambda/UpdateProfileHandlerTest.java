package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_UPDATE_PROFILE_REQUEST_ERROR;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_UPDATE_PROFILE_REQUEST_RECEIVED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_UPDATE_PROFILE_TERMS_CONDS_ACCEPTANCE;
import static uk.gov.di.authentication.frontendapi.entity.UpdateProfileType.UPDATE_TERMS_CONDS;
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.INTERNAL_COMMON_SUBJECT_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.UK_MOBILE_NUMBER;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.VALID_HEADERS_WITHOUT_AUDIT_ENCODED;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class UpdateProfileHandlerTest {

    private static final boolean UPDATED_TERMS_AND_CONDITIONS_VALUE = true;
    private static final String SESSION_ID = "a-session-id";
    private static final ClientID CLIENT_ID = new ClientID("client-one");
    private static final String CLIENT_NAME = "client-name";
    private static final String INTERNAL_SUBJECT = new Subject().getValue();
    private static final Scope SCOPES =
            new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.OFFLINE_ACCESS);
    private static final String COOKIE = "Cookie";
    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");

    private final Context context = mock(Context.class);
    private UpdateProfileHandler handler;
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final ClientRegistry clientRegistry = mock(ClientRegistry.class);
    private final ClientService clientService = mock(ClientService.class);
    private final AuditService auditService = mock(AuditService.class);

    private final String TERMS_AND_CONDITIONS_VERSION =
            configurationService.getTermsAndConditionsVersion();
    private final Session session = new Session().setEmailAddress(EMAIL);
    private final AuthSessionItem authSession =
            new AuthSessionItem()
                    .withSessionId(SESSION_ID)
                    .withEmailAddress(EMAIL)
                    .withInternalCommonSubjectId(INTERNAL_COMMON_SUBJECT_ID);

    private final AuditContext auditContextWithAllUserInfo =
            new AuditContext(
                    CLIENT_ID.getValue(),
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    INTERNAL_COMMON_SUBJECT_ID,
                    EMAIL,
                    IP_ADDRESS,
                    UK_MOBILE_NUMBER,
                    DI_PERSISTENT_SESSION_ID,
                    Optional.of(ENCODED_DEVICE_DETAILS));

    private final AuditContext auditContextWithOnlyClientSession =
            new AuditContext(
                    "",
                    CLIENT_SESSION_ID,
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    Optional.of(ENCODED_DEVICE_DETAILS));

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
                                        CLIENT_ID.toString(),
                                        EMAIL))));
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
                        clientService,
                        authSessionService);
    }

    @Test
    void shouldReturn204WhenUpdatingTermsAndConditions() {
        usingValidSession();
        usingValidClientSession();
        when(authenticationService.getUserProfileFromEmail(EMAIL))
                .thenReturn(Optional.of(generateUserProfile()));
        when(clientService.getClient(CLIENT_ID.getValue())).thenReturn(Optional.of(clientRegistry));
        when(clientRegistry.getClientID()).thenReturn(CLIENT_ID.getValue());

        var body =
                format(
                        "{ \"email\": \"%s\", \"updateProfileType\": \"%s\", \"profileInformation\": \"%s\" }",
                        EMAIL, UPDATE_TERMS_CONDS, UPDATED_TERMS_AND_CONDITIONS_VALUE);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);

        verify(authenticationService)
                .updateTermsAndConditions(eq(EMAIL), eq(TERMS_AND_CONDITIONS_VERSION));
        assertThat(result, hasStatus(204));
        verify(auditService)
                .submitAuditEvent(
                        AUTH_UPDATE_PROFILE_REQUEST_RECEIVED, auditContextWithOnlyClientSession);
        verify(auditService)
                .submitAuditEvent(
                        AUTH_UPDATE_PROFILE_TERMS_CONDS_ACCEPTANCE, auditContextWithAllUserInfo);
    }

    @Test
    void checkUpdateProfileTermsCondsAcceptanceAuditEventStillEmittedWhenTICFHeaderNotProvided() {
        usingValidSession();
        usingValidClientSession();
        when(authenticationService.getUserProfileFromEmail(EMAIL))
                .thenReturn(Optional.of(generateUserProfile()));
        when(clientService.getClient(CLIENT_ID.getValue())).thenReturn(Optional.of(clientRegistry));
        when(clientRegistry.getClientID()).thenReturn(CLIENT_ID.getValue());

        var body =
                format(
                        "{ \"email\": \"%s\", \"updateProfileType\": \"%s\", \"profileInformation\": \"%s\" }",
                        EMAIL, UPDATE_TERMS_CONDS, UPDATED_TERMS_AND_CONDITIONS_VALUE);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS_WITHOUT_AUDIT_ENCODED, body);

        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);

        assertThat(result, hasStatus(204));
        verify(auditService)
                .submitAuditEvent(
                        AUTH_UPDATE_PROFILE_REQUEST_RECEIVED,
                        auditContextWithOnlyClientSession.withTxmaAuditEncoded(Optional.empty()));

        verify(auditService)
                .submitAuditEvent(
                        AUTH_UPDATE_PROFILE_TERMS_CONDS_ACCEPTANCE,
                        auditContextWithAllUserInfo.withTxmaAuditEncoded(Optional.empty()));
    }

    @Test
    void shouldReturn400WhenRequestIsMissingParameters() {
        usingValidSession();

        var body =
                format(
                        "{ \"email\": \"%s\", \"updateProfileType\": \"%s\"}",
                        EMAIL, UPDATE_TERMS_CONDS);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);
        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
        verify(authenticationService, never())
                .updatePhoneNumber(eq(EMAIL), eq(CommonTestVariables.UK_MOBILE_NUMBER));
        verify(auditService)
                .submitAuditEvent(
                        AUTH_UPDATE_PROFILE_REQUEST_RECEIVED, auditContextWithOnlyClientSession);
        verify(auditService)
                .submitAuditEvent(
                        AUTH_UPDATE_PROFILE_REQUEST_ERROR, auditContextWithOnlyClientSession);
    }

    @Test
    void checkUpdateProfileRequestErrorAuditEventStillEmittedWhenTICFHeaderNotProvided() {
        usingValidSession();
        var body =
                format(
                        "{ \"email\": \"%s\", \"updateProfileType\": \"%s\"}",
                        EMAIL, UPDATE_TERMS_CONDS);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS_WITHOUT_AUDIT_ENCODED, body);

        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);

        assertThat(result, hasStatus(400));
        verify(auditService)
                .submitAuditEvent(
                        AUTH_UPDATE_PROFILE_REQUEST_RECEIVED,
                        auditContextWithOnlyClientSession.withTxmaAuditEncoded(Optional.empty()));
        verify(auditService)
                .submitAuditEvent(
                        AUTH_UPDATE_PROFILE_REQUEST_ERROR,
                        auditContextWithOnlyClientSession.withTxmaAuditEncoded(Optional.empty()));
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));

        when(authSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(authSession));
    }

    private void usingValidClientSession() {
        var authRequest =
                new AuthenticationRequest.Builder(
                                new ResponseType(ResponseType.Value.CODE),
                                SCOPES,
                                CLIENT_ID,
                                REDIRECT_URI)
                        .state(new State())
                        .nonce(new Nonce())
                        .build();
        var clientSession =
                new ClientSession(
                        authRequest.toParameters(),
                        LocalDateTime.now(),
                        mock(VectorOfTrust.class),
                        CLIENT_NAME);
        when(clientSessionService.getClientSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(clientSession));
    }

    private APIGatewayProxyResponseEvent makeHandlerRequest(APIGatewayProxyRequestEvent event) {
        var response = handler.handleRequest(event, context);
        return response;
    }

    private UserProfile generateUserProfile() {
        return new UserProfile()
                .withEmail(EMAIL)
                .withEmailVerified(true)
                .withPhoneNumber(CommonTestVariables.UK_MOBILE_NUMBER)
                .withEmailVerified(true)
                .withPublicSubjectID(new Subject().getValue())
                .withSubjectID(INTERNAL_SUBJECT);
    }
}
