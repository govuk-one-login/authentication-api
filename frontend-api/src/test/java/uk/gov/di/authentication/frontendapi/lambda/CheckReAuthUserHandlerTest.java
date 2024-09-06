package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.CheckReauthUserRequest;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.List;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.VALID_HEADERS_WITHOUT_AUDIT_ENCODED;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class CheckReAuthUserHandlerTest {
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final Context context = mock(Context.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final AuthenticationAttemptsService authenticationAttemptsService =
            mock(AuthenticationAttemptsService.class);
    private final ClientService clientService = mock(ClientService.class);

    private static final String CLIENT_ID = "test-client-id";
    private static final String EMAIL_USED_TO_SIGN_IN = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String DIFFERENT_EMAIL_USED_TO_REAUTHENTICATE =
            "not.signedin.email@digital.cabinet-office.gov.uk";
    private static final String TEST_SUBJECT_ID = "subject-id";
    private static final String INTERNAL_SECTOR_URI = "http://www.example.com";
    private static final String TEST_RP_PAIRWISE_ID = "TEST_RP_PAIRWISE_ID";

    private final Session session =
            new Session(SESSION_ID)
                    .setEmailAddress(EMAIL_USED_TO_SIGN_IN)
                    .setInternalCommonSubjectIdentifier(TEST_SUBJECT_ID);

    private final AuditContext testAuditContextWithoutAuditEncoded =
            new AuditContext(
                    CLIENT_ID,
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    AuditService.UNKNOWN,
                    EMAIL_USED_TO_SIGN_IN,
                    IP_ADDRESS,
                    AuditService.UNKNOWN,
                    DI_PERSISTENT_SESSION_ID,
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
        var userProfile = generateUserProfile();
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL_USED_TO_SIGN_IN))
                .thenReturn(Optional.of(userProfile));
        when(authenticationService.getUserProfileByEmail(EMAIL_USED_TO_SIGN_IN))
                .thenReturn(userProfile);
        when(authenticationService.getOrGenerateSalt(any(UserProfile.class))).thenReturn(SALT);

        when(userContext.getClient()).thenReturn(Optional.of(clientRegistry));
        when(userContext.getClientId()).thenReturn(CLIENT_ID);
        when(userContext.getSession()).thenReturn(session);
        when(userContext.getClientSessionId()).thenReturn(CLIENT_SESSION_ID);
        when(userContext.getTxmaAuditEncoded()).thenReturn(ENCODED_DEVICE_DETAILS);

        when(configurationService.getMaxEmailReAuthRetries()).thenReturn(5);
        when(configurationService.getMaxPasswordRetries()).thenReturn(6);

        when(configurationService.supportReauthSignoutEnabled()).thenReturn(true);

        handler =
                new CheckReAuthUserHandler(
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        authenticationService,
                        auditService,
                        authenticationAttemptsService);
    }

    @Test
    void shouldReturn200ForSuccessfulReAuthRequest() {
        when(configurationService.isAuthenticationAttemptsServiceEnabled()).thenReturn(true);
        var body = format("{ \"email\": \"%s\" }", EMAIL_USED_TO_SIGN_IN);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

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
                        new CheckReauthUserRequest(EMAIL_USED_TO_SIGN_IN, expectedRpPairwiseSub),
                        userContext);

        assertEquals(200, result.getStatusCode());

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_REAUTHENTICATION_SUCCESSFUL,
                        testAuditContextWithAuditEncoded);

        verify(authenticationService, atLeastOnce())
                .getUserProfileByEmailMaybe(EMAIL_USED_TO_SIGN_IN);
    }

    @Test
    void checkAuditEventStillEmittedWhenTICFHeaderNotProvided() {
        when(configurationService.isAuthenticationAttemptsServiceEnabled()).thenReturn(true);
        var body = format("{ \"email\": \"%s\" }", EMAIL_USED_TO_SIGN_IN);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS_WITHOUT_AUDIT_ENCODED, body);

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
                        new CheckReauthUserRequest(EMAIL_USED_TO_SIGN_IN, expectedRpPairwiseSub),
                        userContext);

        assertEquals(200, result.getStatusCode());

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_REAUTHENTICATION_SUCCESSFUL,
                        testAuditContextWithoutAuditEncoded);
    }

    @Test
    void shouldReturn404ForWhenUserNotFound() {
        when(configurationService.isAuthenticationAttemptsServiceEnabled()).thenReturn(true);
        var body = format("{ \"email\": \"%s\" }", EMAIL_USED_TO_SIGN_IN);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        when(authenticationService.getUserProfileByEmailMaybe(EMAIL_USED_TO_SIGN_IN))
                .thenReturn(Optional.empty());

        var result =
                handler.handleRequestWithUserContext(
                        event,
                        context,
                        new CheckReauthUserRequest(EMAIL_USED_TO_SIGN_IN, TEST_RP_PAIRWISE_ID),
                        userContext);

        assertEquals(404, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1056));

        verify(authenticationService, atLeastOnce())
                .getUserProfileByEmailMaybe(EMAIL_USED_TO_SIGN_IN);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_REAUTHENTICATION_INVALID,
                        testAuditContextWithAuditEncoded);
    }

    @Test
    void shouldReturn400WhenUserHasEnteredEmailTooManyTimes() {
        when(configurationService.isAuthenticationAttemptsServiceEnabled()).thenReturn(true);
        var body = format("{ \"email\": \"%s\" }", EMAIL_USED_TO_SIGN_IN);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);
        var userProfile = generateUserProfile();

        when(authenticationService.getUserProfileByEmailMaybe(EMAIL_USED_TO_SIGN_IN))
                .thenReturn(Optional.of(userProfile));
        when(authenticationService.getUserProfileByEmail(EMAIL_USED_TO_SIGN_IN))
                .thenReturn(userProfile);
        when(authenticationAttemptsService.getCount(
                        TEST_SUBJECT_ID, JourneyType.REAUTHENTICATION, CountType.ENTER_EMAIL))
                .thenReturn(5);
        var result =
                handler.handleRequestWithUserContext(
                        event,
                        context,
                        new CheckReauthUserRequest(EMAIL_USED_TO_SIGN_IN, TEST_RP_PAIRWISE_ID),
                        userContext);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1057));

        verify(authenticationService, atLeastOnce())
                .getUserProfileByEmailMaybe(EMAIL_USED_TO_SIGN_IN);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_ACCOUNT_TEMPORARILY_LOCKED,
                        testAuditContextWithAuditEncoded,
                        AuditService.MetadataPair.pair(
                                "number_of_attempts_user_allowed_to_login", 5));
    }

    @Test
    void shouldReturn400WhenUserHasBeenBlockedForPasswordRetries() {
        when(configurationService.isAuthenticationAttemptsServiceEnabled()).thenReturn(true);
        var body = format("{ \"email\": \"%s\" }", EMAIL_USED_TO_SIGN_IN);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);
        var userProfile = generateUserProfile();

        when(authenticationService.getUserProfileByEmailMaybe(EMAIL_USED_TO_SIGN_IN))
                .thenReturn(Optional.of(userProfile));
        when(authenticationAttemptsService.getCount(
                        TEST_SUBJECT_ID, JourneyType.REAUTHENTICATION, CountType.ENTER_PASSWORD))
                .thenReturn(6);

        when(clientRegistry.getRedirectUrls()).thenReturn(List.of(INTERNAL_SECTOR_URI));

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
                        new CheckReauthUserRequest(EMAIL_USED_TO_SIGN_IN, expectedRpPairwiseSub),
                        userContext);

        assertEquals(400, result.getStatusCode());
        var expectedErrorResponse = ErrorResponse.ERROR_1057;
        assertThat(result, hasJsonBody(expectedErrorResponse));
    }

    @Test
    void shouldReturn404ForWhenUserDoesNotMatch() {
        when(configurationService.isAuthenticationAttemptsServiceEnabled()).thenReturn(true);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, null);

        var result =
                handler.handleRequestWithUserContext(
                        event,
                        context,
                        new CheckReauthUserRequest(
                                DIFFERENT_EMAIL_USED_TO_REAUTHENTICATE, TEST_RP_PAIRWISE_ID),
                        userContext);

        assertEquals(404, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1056));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_REAUTHENTICATION_INVALID,
                        testAuditContextWithAuditEncoded);
    }

    private UserProfile generateUserProfile() {
        return new UserProfile()
                .withEmail(EMAIL_USED_TO_SIGN_IN)
                .withEmailVerified(true)
                .withPhoneNumberVerified(true)
                .withPublicSubjectID(new Subject().getValue())
                .withSubjectID(TEST_SUBJECT_ID);
    }
}
