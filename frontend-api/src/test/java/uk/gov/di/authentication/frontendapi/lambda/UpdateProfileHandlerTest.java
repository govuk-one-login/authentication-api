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
import uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.AuditService;
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
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.UPDATE_PROFILE_REQUEST_ERROR;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.UPDATE_PROFILE_REQUEST_RECEIVED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.UPDATE_PROFILE_TERMS_CONDS_ACCEPTANCE;
import static uk.gov.di.authentication.frontendapi.entity.UpdateProfileType.UPDATE_TERMS_CONDS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.PERSISTENT_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.TEST_CLIENT_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.TEST_CLIENT_NAME;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.UK_MOBILE_NUMBER;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.validHeaders;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.validHeadersWithoutTxmaAuditEncoded;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class UpdateProfileHandlerTest {

    private static final boolean UPDATED_TERMS_AND_CONDITIONS_VALUE = true;
    private static final String INTERNAL_SUBJECT = new Subject().getValue();
    private static final Scope SCOPES =
            new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.OFFLINE_ACCESS);
    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private final String expectedCommonSubject =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    INTERNAL_SUBJECT, "test.account.gov.uk", SaltHelper.generateNewSalt());
    private final Context context = mock(Context.class);
    private UpdateProfileHandler handler;
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final ClientRegistry clientRegistry = mock(ClientRegistry.class);
    private final ClientService clientService = mock(ClientService.class);
    private final AuditService auditService = mock(AuditService.class);

    private final String TERMS_AND_CONDITIONS_VERSION =
            configurationService.getTermsAndConditionsVersion();
    private final Session session =
            new Session(SESSION_ID)
                    .setEmailAddress(EMAIL)
                    .setInternalCommonSubjectIdentifier(expectedCommonSubject);

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
                                        SESSION_ID, CLIENT_SESSION_ID, TEST_CLIENT_ID, EMAIL))));
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
    void shouldReturn204WhenUpdatingTermsAndConditions() {
        usingValidSession();
        usingValidClientSession();
        when(authenticationService.getUserProfileFromEmail(EMAIL))
                .thenReturn(Optional.of(generateUserProfile()));
        when(clientService.getClient(TEST_CLIENT_ID)).thenReturn(Optional.of(clientRegistry));
        when(clientRegistry.getClientID()).thenReturn(TEST_CLIENT_ID);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(validHeaders(session));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"updateProfileType\": \"%s\", \"profileInformation\": \"%s\" }",
                        EMAIL, UPDATE_TERMS_CONDS, UPDATED_TERMS_AND_CONDITIONS_VALUE));

        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);

        verify(authenticationService)
                .updateTermsAndConditions(eq(EMAIL), eq(TERMS_AND_CONDITIONS_VERSION));
        assertThat(result, hasStatus(204));
        verify(auditService)
                .submitAuditEvent(
                        UPDATE_PROFILE_REQUEST_RECEIVED,
                        "",
                        CLIENT_SESSION_ID,
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        new AuditService.RestrictedSection(Optional.of(ENCODED_DEVICE_DETAILS)));
        verify(auditService)
                .submitAuditEvent(
                        UPDATE_PROFILE_TERMS_CONDS_ACCEPTANCE,
                        TEST_CLIENT_ID,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        expectedCommonSubject,
                        EMAIL,
                        "",
                        CommonTestVariables.UK_MOBILE_NUMBER,
                        PERSISTENT_ID,
                        new AuditService.RestrictedSection(Optional.of(ENCODED_DEVICE_DETAILS)));
    }

    @Test
    void checkUpdateProfileTermsCondsAcceptanceAuditEventStillEmittedWhenTICFHeaderNotProvided() {
        usingValidSession();
        usingValidClientSession();
        when(authenticationService.getUserProfileFromEmail(EMAIL))
                .thenReturn(Optional.of(generateUserProfile()));
        when(clientService.getClient(TEST_CLIENT_ID)).thenReturn(Optional.of(clientRegistry));
        when(clientRegistry.getClientID()).thenReturn(TEST_CLIENT_ID);

        var event = new APIGatewayProxyRequestEvent();

        event.setHeaders(validHeadersWithoutTxmaAuditEncoded(session));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"updateProfileType\": \"%s\", \"profileInformation\": \"%s\" }",
                        EMAIL, UPDATE_TERMS_CONDS, UPDATED_TERMS_AND_CONDITIONS_VALUE));

        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);

        assertThat(result, hasStatus(204));
        verify(auditService)
                .submitAuditEvent(
                        UPDATE_PROFILE_REQUEST_RECEIVED,
                        "",
                        CLIENT_SESSION_ID,
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        AuditService.RestrictedSection.empty);

        verify(auditService)
                .submitAuditEvent(
                        UPDATE_PROFILE_TERMS_CONDS_ACCEPTANCE,
                        TEST_CLIENT_ID,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        expectedCommonSubject,
                        EMAIL,
                        "",
                        UK_MOBILE_NUMBER,
                        PERSISTENT_ID,
                        AuditService.RestrictedSection.empty);
    }

    @Test
    void shouldReturn400WhenRequestIsMissingParameters() {
        usingValidSession();

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(validHeaders(session));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"updateProfileType\": \"%s\"}",
                        EMAIL, UPDATE_TERMS_CONDS));
        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
        verify(authenticationService, never())
                .updatePhoneNumber(eq(EMAIL), eq(CommonTestVariables.UK_MOBILE_NUMBER));
        verify(auditService)
                .submitAuditEvent(
                        UPDATE_PROFILE_REQUEST_RECEIVED,
                        "",
                        CLIENT_SESSION_ID,
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        new AuditService.RestrictedSection(Optional.of(ENCODED_DEVICE_DETAILS)));
        verify(auditService)
                .submitAuditEvent(
                        UPDATE_PROFILE_REQUEST_ERROR,
                        "",
                        CLIENT_SESSION_ID,
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        new AuditService.RestrictedSection(Optional.of(ENCODED_DEVICE_DETAILS)));
    }

    @Test
    void checkUpdateProfileRequestErrorAuditEventStillEmittedWhenTICFHeaderNotProvided() {
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(validHeadersWithoutTxmaAuditEncoded(session));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"updateProfileType\": \"%s\"}",
                        EMAIL, UPDATE_TERMS_CONDS));

        APIGatewayProxyResponseEvent result = makeHandlerRequest(event);

        assertThat(result, hasStatus(400));
        verify(auditService)
                .submitAuditEvent(
                        UPDATE_PROFILE_REQUEST_RECEIVED,
                        "",
                        CLIENT_SESSION_ID,
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        AuditService.RestrictedSection.empty);
        verify(auditService)
                .submitAuditEvent(
                        UPDATE_PROFILE_REQUEST_ERROR,
                        "",
                        CLIENT_SESSION_ID,
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        AuditService.RestrictedSection.empty);
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
    }

    private void usingValidClientSession() {
        var authRequest =
                new AuthenticationRequest.Builder(
                                new ResponseType(ResponseType.Value.CODE),
                                SCOPES,
                                new ClientID(TEST_CLIENT_ID),
                                REDIRECT_URI)
                        .state(new State())
                        .nonce(new Nonce())
                        .build();
        var clientSession =
                new ClientSession(
                        authRequest.toParameters(),
                        LocalDateTime.now(),
                        mock(VectorOfTrust.class),
                        TEST_CLIENT_NAME);
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
