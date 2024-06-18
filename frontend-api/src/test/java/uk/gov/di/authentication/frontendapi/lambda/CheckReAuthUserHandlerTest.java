package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.CheckReauthUserRequest;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.PERSISTENT_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.TEST_CLIENT_ID;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class CheckReAuthUserHandlerTest {

    private static final String TEST_SUBJECT_ID = "subject-id";
    private static final String INTERNAL_SECTOR_URI = "http://www.example.com";
    private static final String TEST_RP_PAIRWISE_ID = "TEST_RP_PAIRWISE_ID";

    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final Context context = mock(Context.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ClientService clientService = mock(ClientService.class);

    private final Session session = new Session(IdGenerator.generate()).setEmailAddress(EMAIL);
    private final AuditContext testAuditContextWithoutAuditEncoded =
            new AuditContext(
                    TEST_CLIENT_ID,
                    CLIENT_SESSION_ID,
                    session.getSessionId(),
                    AuditService.UNKNOWN,
                    EMAIL,
                    AuditService.UNKNOWN,
                    AuditService.UNKNOWN,
                    PERSISTENT_ID,
                    Optional.empty());

    private final AuditContext testAuditContextWithAuditEncoded =
            testAuditContextWithoutAuditEncoded.withTxmaAuditEncoded(
                    Optional.of(ENCODED_DEVICE_DETAILS));
    private final UserContext userContext = mock(UserContext.class);
    private final ClientRegistry clientRegistry = mock(ClientRegistry.class);
    private static final byte[] SALT = SaltHelper.generateNewSalt();

    private CheckReAuthUserHandler handler;

    @BeforeEach
    public void setUp() {
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
        when(authenticationService.getOrGenerateSalt(any(UserProfile.class))).thenReturn(SALT);
        when(clientRegistry.getClientID()).thenReturn(TEST_CLIENT_ID);
        when(userContext.getClient()).thenReturn(Optional.of(clientRegistry));
        when(userContext.getClientId()).thenReturn(TEST_CLIENT_ID);
        when(clientService.getClient(TEST_CLIENT_ID)).thenReturn(Optional.of(clientRegistry));
        when(userContext.getSession()).thenReturn(session);
        when(userContext.getClientSessionId()).thenReturn(CLIENT_SESSION_ID);
        when(userContext.getTxmaAuditEncoded()).thenReturn(ENCODED_DEVICE_DETAILS);
        var userProfile = generateUserProfile();
        userProfile.setSubjectID(TEST_SUBJECT_ID);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(configurationService.getMaxEmailReAuthRetries()).thenReturn(5);
        when(configurationService.getMaxPasswordRetries()).thenReturn(6);
        handler =
                new CheckReAuthUserHandler(
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        authenticationService,
                        auditService,
                        codeStorageService);
    }

    @Test
    void shouldReturn200ForSuccessfulReAuthRequest() {
        var context = mock(Context.class);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(getHeaders());
        event.setBody(format("{ \"email\": \"%s\" }", EMAIL));

        when(configurationService.getEnvironment()).thenReturn("build");
        when(configurationService.getInternalSectorUri()).thenReturn(INTERNAL_SECTOR_URI);
        when(clientRegistry.getRedirectUrls()).thenReturn(List.of(INTERNAL_SECTOR_URI));

        var userProfile = generateUserProfile();
        var expectedRpPairwiseSub =
                ClientSubjectHelper.getSubject(
                                userProfile,
                                clientRegistry,
                                authenticationService,
                                INTERNAL_SECTOR_URI)
                        .getValue();

        var result =
                handler.handleRequestWithUserContext(
                        event,
                        context,
                        new CheckReauthUserRequest(EMAIL, expectedRpPairwiseSub),
                        userContext);
        assertEquals(200, result.getStatusCode());

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.REAUTHENTICATION_SUCCESSFUL,
                        testAuditContextWithAuditEncoded);
    }

    @Test
    void checkAuditEventStillEmittedWhenTICFHeaderNotProvided() {
        var context = mock(Context.class);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(getHeaders());
        event.setBody(format("{ \"email\": \"%s\" }", EMAIL));

        when(configurationService.getEnvironment()).thenReturn("build");
        when(configurationService.getInternalSectorUri()).thenReturn(INTERNAL_SECTOR_URI);
        when(clientRegistry.getRedirectUrls()).thenReturn(List.of(INTERNAL_SECTOR_URI));
        when(userContext.getTxmaAuditEncoded()).thenReturn(null);

        var userProfile = generateUserProfile();
        var expectedRpPairwiseSub =
                ClientSubjectHelper.getSubject(
                                userProfile,
                                clientRegistry,
                                authenticationService,
                                INTERNAL_SECTOR_URI)
                        .getValue();

        var result =
                handler.handleRequestWithUserContext(
                        event,
                        context,
                        new CheckReauthUserRequest(EMAIL, expectedRpPairwiseSub),
                        userContext);

        assertEquals(200, result.getStatusCode());

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.REAUTHENTICATION_SUCCESSFUL,
                        testAuditContextWithoutAuditEncoded);
    }

    @Test
    void shouldReturn404ForWhenUserNotFound() {
        var context = mock(Context.class);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(getHeaders());
        event.setBody(format("{ \"email\": \"%s\" }", EMAIL));

        when(authenticationService.getUserProfileByEmailMaybe(EMAIL)).thenReturn(Optional.empty());

        var result =
                handler.handleRequestWithUserContext(
                        event,
                        context,
                        new CheckReauthUserRequest(EMAIL, TEST_RP_PAIRWISE_ID),
                        userContext);
        assertEquals(404, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1056));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.REAUTHENTICATION_INVALID,
                        testAuditContextWithAuditEncoded);
    }

    @Test
    void shouldReturn400WhenUserHasEnteredEmailTooManyTimes() {
        var context = mock(Context.class);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(getHeaders());
        event.setBody(format("{ \"email\": \"%s\" }", EMAIL));
        var userProfile = generateUserProfile();
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(codeStorageService.getIncorrectEmailCount(any())).thenReturn(5);

        var result =
                handler.handleRequestWithUserContext(
                        event,
                        context,
                        new CheckReauthUserRequest(EMAIL, TEST_RP_PAIRWISE_ID),
                        userContext);
        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1057));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.ACCOUNT_TEMPORARILY_LOCKED,
                        testAuditContextWithAuditEncoded,
                        AuditService.MetadataPair.pair(
                                "number_of_attempts_user_allowed_to_login", 5));
    }

    @Test
    void shouldReturn400WhenUserHasBeenBlockedForPasswordRetries() {
        var context = mock(Context.class);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(getHeaders());
        event.setBody(format("{ \"email\": \"%s\" }", EMAIL));
        var userProfile = generateUserProfile();
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(codeStorageService.getIncorrectPasswordCountReauthJourney(any())).thenReturn(6);

        var result =
                handler.handleRequestWithUserContext(
                        event,
                        context,
                        new CheckReauthUserRequest(EMAIL, TEST_RP_PAIRWISE_ID),
                        userContext);
        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1045));
    }

    @Test
    void shouldReturn404ForWhenUserDoesNotMatch() {
        var context = mock(Context.class);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(getHeaders());
        event.setBody(format("{ \"email\": \"%s\" }", EMAIL));

        when(configurationService.getInternalSectorUri()).thenReturn(INTERNAL_SECTOR_URI);
        when(configurationService.getEnvironment()).thenReturn("build");
        when(clientRegistry.getRedirectUrls()).thenReturn(List.of("http://test.example.com"));

        var result =
                handler.handleRequestWithUserContext(
                        event,
                        context,
                        new CheckReauthUserRequest(EMAIL, TEST_RP_PAIRWISE_ID),
                        userContext);
        assertEquals(404, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1056));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.REAUTHENTICATION_INVALID,
                        testAuditContextWithAuditEncoded);
    }

    private UserProfile generateUserProfile() {
        return new UserProfile()
                .withEmail(EMAIL)
                .withEmailVerified(true)
                .withPhoneNumberVerified(true)
                .withPublicSubjectID(new Subject().getValue())
                .withSubjectID(TEST_SUBJECT_ID);
    }

    private Map<String, String> getHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", session.getSessionId());
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID);
        return headers;
    }
}
