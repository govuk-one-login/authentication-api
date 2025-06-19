package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.CheckReauthUserRequest;
import uk.gov.di.authentication.shared.domain.CloudwatchMetrics;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.FAILURE_REASON;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class CheckReAuthUserHandlerTest {
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuthenticationAttemptsService authenticationAttemptsService =
            mock(AuthenticationAttemptsService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);

    private static final String CLIENT_ID = "test-client-id";
    private static final String EMAIL_USED_TO_SIGN_IN = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String DIFFERENT_EMAIL_USED_TO_REAUTHENTICATE =
            "not.signedin.email@digital.cabinet-office.gov.uk";
    private static final String TEST_SUBJECT_ID = "subject-id";
    private static final String INTERNAL_SECTOR_URI = "http://www.example.com";
    private static final String TEST_RP_PAIRWISE_ID = "TEST_RP_PAIRWISE_ID";
    private static final UserProfile USER_PROFILE =
            new UserProfile()
                    .withEmail(EMAIL_USED_TO_SIGN_IN)
                    .withEmailVerified(true)
                    .withPhoneNumberVerified(true)
                    .withPublicSubjectID(new Subject().getValue())
                    .withSubjectID(TEST_SUBJECT_ID);

    // Here the body doesn't matter, as the method we're testing already assumes we've extracted
    // the body into the relevant request object
    private static final APIGatewayProxyRequestEvent API_REQUEST_EVENT_WITH_VALID_HEADERS =
            apiRequestEventWithHeadersAndBody(VALID_HEADERS, null);

    private final AuthSessionItem authSession =
            new AuthSessionItem()
                    .withSessionId(SESSION_ID)
                    .withEmailAddress(EMAIL_USED_TO_SIGN_IN)
                    .withClientId(CLIENT_ID);

    private final AuditContext testAuditContextWithoutAuditEncoded =
            new AuditContext(
                    CLIENT_ID,
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    TEST_SUBJECT_ID,
                    EMAIL_USED_TO_SIGN_IN,
                    IP_ADDRESS,
                    AuditService.UNKNOWN,
                    DI_PERSISTENT_SESSION_ID,
                    Optional.empty(),
                    new ArrayList<>());

    private final AuditContext testAuditContextWithAuditEncoded =
            testAuditContextWithoutAuditEncoded.withTxmaAuditEncoded(
                    Optional.of(ENCODED_DEVICE_DETAILS));

    private final UserContext userContext = mock(UserContext.class);

    private final ClientRegistry clientRegistry = mock(ClientRegistry.class);

    private String expectedRpPairwiseSub;

    private static final byte[] SALT = SaltHelper.generateNewSalt();

    private CheckReAuthUserHandler handler;

    private static final int MAX_RETRIES = 6;

    @BeforeEach
    public void setUp() {
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL_USED_TO_SIGN_IN))
                .thenReturn(Optional.of(USER_PROFILE));
        when(authenticationService.getUserProfileByEmail(EMAIL_USED_TO_SIGN_IN))
                .thenReturn(USER_PROFILE);
        when(authenticationService.getOrGenerateSalt(any(UserProfile.class))).thenReturn(SALT);

        when(userContext.getClient()).thenReturn(Optional.of(clientRegistry));
        when(userContext.getAuthSession()).thenReturn(authSession);
        when(userContext.getClientSessionId()).thenReturn(CLIENT_SESSION_ID);
        when(userContext.getTxmaAuditEncoded()).thenReturn(ENCODED_DEVICE_DETAILS);

        when(configurationService.getEnvironment()).thenReturn("test");
        when(configurationService.getMaxEmailReAuthRetries()).thenReturn(MAX_RETRIES);
        when(configurationService.getMaxPasswordRetries()).thenReturn(MAX_RETRIES);
        when(configurationService.getCodeMaxRetries()).thenReturn(MAX_RETRIES);
        when(configurationService.supportReauthSignoutEnabled()).thenReturn(true);

        when(clientRegistry.getRedirectUrls()).thenReturn(List.of(INTERNAL_SECTOR_URI));

        expectedRpPairwiseSub =
                ClientSubjectHelper.getSubject(
                                USER_PROFILE,
                                clientRegistry,
                                authSession,
                                authenticationService,
                                INTERNAL_SECTOR_URI)
                        .getValue();

        handler =
                new CheckReAuthUserHandler(
                        configurationService,
                        clientService,
                        authenticationService,
                        auditService,
                        authenticationAttemptsService,
                        cloudwatchMetricsService,
                        authSessionService);
    }

    @Test
    void shouldReturn200ForSuccessfulReAuthRequest() {
        var existingCountOfIncorrectEmails = 1;
        setupExistingEnterEmailAttemptsCountForIdentifier(
                existingCountOfIncorrectEmails, TEST_SUBJECT_ID);

        var result =
                handler.handleRequestWithUserContext(
                        API_REQUEST_EVENT_WITH_VALID_HEADERS,
                        context,
                        new CheckReauthUserRequest(EMAIL_USED_TO_SIGN_IN, expectedRpPairwiseSub),
                        userContext);

        assertEquals(200, result.getStatusCode());

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_REAUTH_ACCOUNT_IDENTIFIED,
                        testAuditContextWithAuditEncoded,
                        pair("rpPairwiseId", expectedRpPairwiseSub),
                        pair("incorrect_email_attempt_count", existingCountOfIncorrectEmails));

        verify(authenticationService, atLeastOnce())
                .getUserProfileByEmailMaybe(EMAIL_USED_TO_SIGN_IN);
    }

    @Test
    void shouldReturn404ForWhenUserNotFound() {
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL_USED_TO_SIGN_IN))
                .thenReturn(Optional.empty());

        setupExistingEnterEmailAttemptsCountForIdentifier(1, TEST_RP_PAIRWISE_ID);

        var result =
                handler.handleRequestWithUserContext(
                        API_REQUEST_EVENT_WITH_VALID_HEADERS,
                        context,
                        new CheckReauthUserRequest(EMAIL_USED_TO_SIGN_IN, TEST_RP_PAIRWISE_ID),
                        userContext);

        assertEquals(404, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1056));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_REAUTH_INCORRECT_EMAIL_ENTERED,
                        testAuditContextWithAuditEncoded.withUserId(AuditService.UNKNOWN),
                        pair("rpPairwiseId", TEST_RP_PAIRWISE_ID),
                        pair("incorrect_email_attempt_count", 1),
                        pair("user_supplied_email", EMAIL_USED_TO_SIGN_IN, true));
    }

    @Test
    void shouldReturn400WhenUserHasEnteredEmailTooManyTimes() {
        setupExistingEnterEmailAttemptsCountForSubjectIdAndPairwiseId(MAX_RETRIES, 0);
        var result =
                handler.handleRequestWithUserContext(
                        API_REQUEST_EVENT_WITH_VALID_HEADERS,
                        context,
                        new CheckReauthUserRequest(EMAIL_USED_TO_SIGN_IN, TEST_RP_PAIRWISE_ID),
                        userContext);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1057));

        // In the case where a user is already locked out, we do not emit this event
        // The case where the event is emitted is tested in integration tests
        verify(auditService, never())
                .submitAuditEvent(
                        eq(FrontendAuditableEvent.AUTH_REAUTH_INCORRECT_EMAIL_LIMIT_BREACHED),
                        any(),
                        any(AuditService.MetadataPair[].class));
        verify(auditService, times(1))
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_REAUTH_FAILED,
                        testAuditContextWithAuditEncoded,
                        AuditService.MetadataPair.pair("rpPairwiseId", TEST_RP_PAIRWISE_ID),
                        AuditService.MetadataPair.pair("incorrect_email_attempt_count", 6),
                        AuditService.MetadataPair.pair("incorrect_password_attempt_count", 0),
                        AuditService.MetadataPair.pair("incorrect_otp_code_attempt_count", 0),
                        AuditService.MetadataPair.pair("failure-reason", "incorrect_email"));
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        CloudwatchMetrics.REAUTH_FAILED.getValue(),
                        Map.of(
                                ENVIRONMENT.getValue(),
                                configurationService.getEnvironment(),
                                FAILURE_REASON.getValue(),
                                "incorrect_email"));
    }

    @Test
    void shouldReturn400WhenUserHasEnteredEmailTooManyTimesAcrossRpPairwiseIdAndSubjectId() {
        setupExistingEnterEmailAttemptsCountForSubjectIdAndPairwiseId(MAX_RETRIES - 1, 1);
        var result =
                handler.handleRequestWithUserContext(
                        API_REQUEST_EVENT_WITH_VALID_HEADERS,
                        context,
                        new CheckReauthUserRequest(EMAIL_USED_TO_SIGN_IN, TEST_RP_PAIRWISE_ID),
                        userContext);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1057));

        // In the case where a user is already locked out, we do not emit this event
        // The case where the event is emitted is tested in integration tests
        verify(auditService, never())
                .submitAuditEvent(
                        eq(FrontendAuditableEvent.AUTH_REAUTH_INCORRECT_EMAIL_LIMIT_BREACHED),
                        any(),
                        any(AuditService.MetadataPair[].class));
        verify(auditService, times(1))
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_REAUTH_FAILED,
                        testAuditContextWithAuditEncoded,
                        AuditService.MetadataPair.pair("rpPairwiseId", TEST_RP_PAIRWISE_ID),
                        AuditService.MetadataPair.pair("incorrect_email_attempt_count", 6),
                        AuditService.MetadataPair.pair("incorrect_password_attempt_count", 0),
                        AuditService.MetadataPair.pair("incorrect_otp_code_attempt_count", 0),
                        AuditService.MetadataPair.pair("failure-reason", "incorrect_email"));
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        CloudwatchMetrics.REAUTH_FAILED.getValue(),
                        Map.of(
                                ENVIRONMENT.getValue(),
                                configurationService.getEnvironment(),
                                FAILURE_REASON.getValue(),
                                "incorrect_email"));
    }

    @Test
    void shouldReturn400WhenUserHasBeenBlockedForPasswordRetries() {
        when(authenticationAttemptsService.getCountsByJourneyForSubjectIdAndRpPairwiseId(
                        TEST_SUBJECT_ID, expectedRpPairwiseSub, JourneyType.REAUTHENTICATION))
                .thenReturn(Map.of(CountType.ENTER_PASSWORD, MAX_RETRIES));

        var result =
                handler.handleRequestWithUserContext(
                        API_REQUEST_EVENT_WITH_VALID_HEADERS,
                        context,
                        new CheckReauthUserRequest(EMAIL_USED_TO_SIGN_IN, expectedRpPairwiseSub),
                        userContext);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1057));
    }

    @Test
    void shouldReturn400WhenUserHasBeenBlockedForMfaAttempts() {
        when(authenticationAttemptsService.getCountsByJourneyForSubjectIdAndRpPairwiseId(
                        TEST_SUBJECT_ID, expectedRpPairwiseSub, JourneyType.REAUTHENTICATION))
                .thenReturn(Map.of(CountType.ENTER_MFA_CODE, MAX_RETRIES));

        var result =
                handler.handleRequestWithUserContext(
                        API_REQUEST_EVENT_WITH_VALID_HEADERS,
                        context,
                        new CheckReauthUserRequest(EMAIL_USED_TO_SIGN_IN, expectedRpPairwiseSub),
                        userContext);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1057));
    }

    @Test
    void shouldReturn404ForWhenUserDoesNotMatch() {
        setupExistingEnterEmailAttemptsCountForIdentifier(3, TEST_RP_PAIRWISE_ID);

        var result =
                handler.handleRequestWithUserContext(
                        API_REQUEST_EVENT_WITH_VALID_HEADERS,
                        context,
                        new CheckReauthUserRequest(
                                DIFFERENT_EMAIL_USED_TO_REAUTHENTICATE, TEST_RP_PAIRWISE_ID),
                        userContext);

        assertEquals(404, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1056));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_REAUTH_INCORRECT_EMAIL_ENTERED,
                        testAuditContextWithAuditEncoded.withUserId(AuditService.UNKNOWN),
                        pair("rpPairwiseId", TEST_RP_PAIRWISE_ID),
                        pair("incorrect_email_attempt_count", 3),
                        pair("user_supplied_email", DIFFERENT_EMAIL_USED_TO_REAUTHENTICATE, true));
    }

    @Test
    void shouldIncludeTheUserSubjectIdForWhenUserDoesNotMatchButHasAccount() {
        var differentSubjectId = "ANOTHER_SUBJECT_ID";
        setupExistingEnterEmailAttemptsCountForIdentifier(3, TEST_RP_PAIRWISE_ID);
        when(authenticationService.getUserProfileByEmailMaybe(
                        DIFFERENT_EMAIL_USED_TO_REAUTHENTICATE))
                .thenReturn(Optional.of(new UserProfile().withSubjectID(differentSubjectId)));

        var result =
                handler.handleRequestWithUserContext(
                        API_REQUEST_EVENT_WITH_VALID_HEADERS,
                        context,
                        new CheckReauthUserRequest(
                                DIFFERENT_EMAIL_USED_TO_REAUTHENTICATE, TEST_RP_PAIRWISE_ID),
                        userContext);

        assertEquals(404, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1056));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_REAUTH_INCORRECT_EMAIL_ENTERED,
                        testAuditContextWithAuditEncoded.withUserId(AuditService.UNKNOWN),
                        pair("rpPairwiseId", TEST_RP_PAIRWISE_ID),
                        pair("incorrect_email_attempt_count", 3),
                        pair("user_supplied_email", DIFFERENT_EMAIL_USED_TO_REAUTHENTICATE, true),
                        pair("user_id_for_user_supplied_email", differentSubjectId, true));
    }

    private void setupExistingEnterEmailAttemptsCountForIdentifier(int count, String identifier) {
        when(authenticationAttemptsService.getCount(
                        identifier, JourneyType.REAUTHENTICATION, CountType.ENTER_EMAIL))
                .thenReturn(count);
        when(authenticationAttemptsService.getCountsByJourney(
                        identifier, JourneyType.REAUTHENTICATION))
                .thenReturn(Map.of(CountType.ENTER_EMAIL, count));
    }

    private void setupExistingEnterEmailAttemptsCountForSubjectIdAndPairwiseId(
            int subjectIdCount, int pairwiseIdCount) {
        when(authenticationAttemptsService.getCount(
                        TEST_SUBJECT_ID, JourneyType.REAUTHENTICATION, CountType.ENTER_EMAIL))
                .thenReturn(subjectIdCount);
        when(authenticationAttemptsService.getCount(
                        expectedRpPairwiseSub, JourneyType.REAUTHENTICATION, CountType.ENTER_EMAIL))
                .thenReturn(pairwiseIdCount);
        when(authenticationAttemptsService.getCountsByJourneyForSubjectIdAndRpPairwiseId(
                        TEST_SUBJECT_ID, TEST_RP_PAIRWISE_ID, JourneyType.REAUTHENTICATION))
                .thenReturn(Map.of(CountType.ENTER_EMAIL, subjectIdCount + pairwiseIdCount));
    }
}
