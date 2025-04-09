package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.domain.CloudwatchMetrics;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAuthCodeService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REAUTH_SUCCESS;
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.CLIENT_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.UK_MOBILE_NUMBER;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.frontendapi.lambda.CheckEmailFraudBlockHandlerTest.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthenticationAuthCodeHandlerTest {
    private static final String TEST_REDIRECT_URI = "https://redirect_uri.com";
    private static final String TEST_STATE = "xyz";
    private static final String LOCATION = "location";
    private static final String TEST_SUBJECT_ID = "subject-id";
    private static final String TEST_SECTOR_IDENTIFIER = "sectorIdentifier";
    private static final String CALCULATED_PAIRWISE_ID = "some-rp-pairwise-id";
    private static final Long PASSWORD_RESET_TIME = 1696869005821L;

    private AuthenticationAuthCodeHandler handler;
    private static final Json objectMapper = SerializationService.getInstance();
    private final Context context = mock(Context.class);
    private final DynamoAuthCodeService dynamoAuthCodeService = mock(DynamoAuthCodeService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private Session session;
    private AuthSessionItem authSession;
    private final AuditService auditService = mock(AuditService.class);
    private final ClientSession clientSession = mock(ClientSession.class);
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);

    private final AuditContext auditContext =
            new AuditContext(
                    CLIENT_ID,
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    TEST_SUBJECT_ID,
                    EMAIL,
                    IP_ADDRESS,
                    UK_MOBILE_NUMBER,
                    DI_PERSISTENT_SESSION_ID,
                    Optional.of(ENCODED_DEVICE_DETAILS));

    @BeforeEach
    void setUp() throws Json.JsonException {
        session = new Session();
        authSession =
                new AuthSessionItem()
                        .withSessionId(SESSION_ID)
                        .withEmailAddress(CommonTestVariables.EMAIL)
                        .withClientId(CLIENT_ID);
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
        when(clientSessionService.getClientSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(clientSession));
        when(clientService.getClient(CLIENT_ID))
                .thenReturn(Optional.of(new ClientRegistry().withClientID(CLIENT_ID)));
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
        when(authSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(authSession));
        UserProfile userProfile = generateUserProfile();
        when(authenticationService.getUserProfileByEmailMaybe(CommonTestVariables.EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(configurationService.getEnvironment()).thenReturn("test");
        handler =
                new AuthenticationAuthCodeHandler(
                        dynamoAuthCodeService,
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        authenticationService,
                        auditService,
                        cloudwatchMetricsService,
                        authSessionService);
    }

    @Test
    void shouldReturn400ErrorWhenRedirectUriIsInvalid() throws Json.JsonException {
        var body =
                format(
                        "{ \"email\": \"%s\", \"redirect-uri\": \"%s\" }",
                        CommonTestVariables.EMAIL, "");
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1001)));
    }

    @Test
    void shouldReturn400ErrorWhenStateIsInvalid() throws Json.JsonException {
        var body =
                format(
                        "{ \"email\": \"%s\", \"redirect-uri\": \"%s\", \"state\": \"%s\" }",
                        CommonTestVariables.EMAIL, TEST_REDIRECT_URI, "");
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1001)));
    }

    @Test
    void shouldReturn400ErrorClaimsListIsEmpty() throws Json.JsonException {
        var body =
                format(
                        "{ \"email\": \"%s\", \"redirect-uri\": \"%s\", \"state\": \"%s\", \"claims\": [\"%s\"] }",
                        CommonTestVariables.EMAIL, TEST_REDIRECT_URI, TEST_STATE, Optional.empty());
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1001)));
    }

    @Test
    void shouldReturn400ErrorWhenRPSectorUriIsInvalid() throws Json.JsonException {
        var body =
                format(
                        "{ \"email\": \"%s\", \"redirect-uri\": \"%s\", \"state\": \"%s\", \"claims\": [\"%s\"], \"rp-sector-uri\": \"%s\", }",
                        CommonTestVariables.EMAIL,
                        TEST_REDIRECT_URI,
                        TEST_STATE,
                        List.of("email-verified", "email"),
                        "");
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1001)));
    }

    @Test
    void shouldReturn400ErrorWhenUnableToFetchEmailFromUserProfile() throws Json.JsonException {
        when(authenticationService.getUserProfileByEmailMaybe(CommonTestVariables.EMAIL))
                .thenReturn(Optional.empty());
        var event = validAuthCodeRequest();

        var result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1049)));
    }

    @Test
    void shouldReturn200AndSaveNewAuthCodeRequest() throws URISyntaxException {
        when(configurationService.getAuthCodeExpiry()).thenReturn(Long.valueOf(12));
        var userProfile = new UserProfile();
        userProfile.setSubjectID(TEST_SUBJECT_ID);
        when(authenticationService.getUserProfileFromEmail(CommonTestVariables.EMAIL))
                .thenReturn(Optional.of(userProfile));
        var event = validAuthCodeRequest();

        var result = handler.handleRequest(event, context);

        verify(dynamoAuthCodeService, times(1))
                .saveAuthCode(
                        eq(userProfile.getSubjectID()),
                        anyString(),
                        anyList(),
                        eq(false),
                        anyString(),
                        eq(false),
                        eq(null),
                        eq(CLIENT_SESSION_ID));
        assertThat(result, hasStatus(200));
        var jsonBody = new JSONObject(result.getBody());
        assertTrue(jsonBody.has(LOCATION));
        var location = jsonBody.get(LOCATION);
        var uri = new URI(location.toString());
        assertTrue(uri.getQuery().contains("code"));
        assertTrue(uri.getQuery().contains("state"));
        assertTrue(uri.getQuery().contains(TEST_STATE));
        assertFalse(uri.getQuery().contains("random_query_parameter"));
        verify(auditService, never())
                .submitAuditEvent(
                        eq(AUTH_REAUTH_SUCCESS), any(), any(AuditService.MetadataPair[].class));
        verify(cloudwatchMetricsService, never())
                .incrementCounter(
                        CloudwatchMetrics.REAUTH_SUCCESS.getValue(),
                        Map.of(ENVIRONMENT.getValue(), configurationService.getEnvironment()));
    }

    @Test
    void shouldSubmitReauthSuccessfulEventAndCleanUpSessionCountsForSuccessfulReauthJourney() {
        try (MockedStatic<ClientSubjectHelper> mockedClientSubjectHelperClass =
                Mockito.mockStatic(ClientSubjectHelper.class)) {
            var userProfile = new UserProfile().withEmail(EMAIL).withPhoneNumber(UK_MOBILE_NUMBER);
            userProfile.setSubjectID(TEST_SUBJECT_ID);
            when(configurationService.getAuthCodeExpiry()).thenReturn(Long.valueOf(12));
            when(configurationService.supportReauthSignoutEnabled()).thenReturn(true);
            when(authenticationService.getUserProfileFromEmail(CommonTestVariables.EMAIL))
                    .thenReturn(Optional.of(userProfile));
            mockedClientSubjectHelperClass
                    .when(
                            () ->
                                    ClientSubjectHelper.getSubject(
                                            eq(userProfile), any(), any(), any()))
                    .thenReturn(new Subject(CALCULATED_PAIRWISE_ID));
            var existingPasswordCount = 1;
            var existingEmailCount = 2;
            authSession.setPreservedReauthCountsForAuditMap(
                    Map.ofEntries(
                            Map.entry(CountType.ENTER_PASSWORD, existingPasswordCount),
                            Map.entry(CountType.ENTER_EMAIL, existingEmailCount)));

            var body =
                    format(
                            "{ \"redirect-uri\": \"%s\", \"state\": \"%s\", \"claims\": [\"%s\"], \"rp-sector-uri\": \"%s\",  \"is-new-account\": \"%s\", \"is-reauth-journey\": %b}",
                            TEST_REDIRECT_URI,
                            TEST_STATE,
                            List.of("email-verified", "email"),
                            TEST_SECTOR_IDENTIFIER,
                            false,
                            true);

            var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

            var result = handler.handleRequest(event, context);

            assertThat(result, hasStatus(200));

            var expectedPairs =
                    new AuditService.MetadataPair[] {
                        pair("rpPairwiseId", CALCULATED_PAIRWISE_ID),
                        pair("incorrect_email_attempt_count", existingEmailCount),
                        pair("incorrect_password_attempt_count", existingPasswordCount),
                        pair("incorrect_otp_code_attempt_count", 0)
                    };

            verify(auditService).submitAuditEvent(AUTH_REAUTH_SUCCESS, auditContext, expectedPairs);
            verify(cloudwatchMetricsService)
                    .incrementCounter(
                            CloudwatchMetrics.REAUTH_SUCCESS.getValue(),
                            Map.of(ENVIRONMENT.getValue(), configurationService.getEnvironment()));
            verify(authSessionService, atLeastOnce())
                    .updateSession(
                            argThat(s -> Objects.isNull(s.getPreservedReauthCountsForAuditMap())));
        }
    }

    @Test
    void
            shouldStillSubmitReauthSuccessfulEventButWithoutCountsForSuccessfulReauthJourneyWhenSessionCountsAreNull() {
        try (MockedStatic<ClientSubjectHelper> mockedClientSubjectHelperClass =
                Mockito.mockStatic(ClientSubjectHelper.class)) {
            var userProfile = new UserProfile().withEmail(EMAIL).withPhoneNumber(UK_MOBILE_NUMBER);
            userProfile.setSubjectID(TEST_SUBJECT_ID);
            when(configurationService.getAuthCodeExpiry()).thenReturn(Long.valueOf(12));
            when(configurationService.supportReauthSignoutEnabled()).thenReturn(true);
            when(authenticationService.getUserProfileFromEmail(CommonTestVariables.EMAIL))
                    .thenReturn(Optional.of(userProfile));
            mockedClientSubjectHelperClass
                    .when(
                            () ->
                                    ClientSubjectHelper.getSubject(
                                            eq(userProfile), any(), any(), any()))
                    .thenReturn(new Subject(CALCULATED_PAIRWISE_ID));
            // This is already the case but just to make it explicit here
            authSession.setPreservedReauthCountsForAuditMap(null);

            var body =
                    format(
                            "{ \"redirect-uri\": \"%s\", \"state\": \"%s\", \"claims\": [\"%s\"], \"rp-sector-uri\": \"%s\",  \"is-new-account\": \"%s\", \"is-reauth-journey\": %b}",
                            TEST_REDIRECT_URI,
                            TEST_STATE,
                            List.of("email-verified", "email"),
                            TEST_SECTOR_IDENTIFIER,
                            false,
                            true);

            var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

            var result = handler.handleRequest(event, context);

            assertThat(result, hasStatus(200));

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_REAUTH_SUCCESS,
                            auditContext,
                            pair("rpPairwiseId", CALCULATED_PAIRWISE_ID));
            verify(cloudwatchMetricsService)
                    .incrementCounter(
                            CloudwatchMetrics.REAUTH_SUCCESS.getValue(),
                            Map.of(ENVIRONMENT.getValue(), configurationService.getEnvironment()));
        }
    }

    @Test
    void shouldNotSubmitReauthSuccessEventForNonReauthJourney() {
        when(configurationService.getAuthCodeExpiry()).thenReturn(Long.valueOf(12));
        when(configurationService.supportReauthSignoutEnabled()).thenReturn(true);
        var userProfile = new UserProfile().withEmail(EMAIL).withPhoneNumber(UK_MOBILE_NUMBER);
        userProfile.setSubjectID(TEST_SUBJECT_ID);
        when(authenticationService.getUserProfileFromEmail(CommonTestVariables.EMAIL))
                .thenReturn(Optional.of(userProfile));

        var result = handler.handleRequest(validAuthCodeRequest(), context);

        assertThat(result, hasStatus(200));

        verify(auditService, never())
                .submitAuditEvent(
                        eq(AUTH_REAUTH_SUCCESS), any(), any(AuditService.MetadataPair[].class));
        verify(cloudwatchMetricsService, never())
                .incrementCounter(
                        CloudwatchMetrics.REAUTH_SUCCESS.getValue(),
                        Map.of(ENVIRONMENT.getValue(), configurationService.getEnvironment()));
    }

    @Test
    void shouldReturn200AndSaveNewAuthCodeRequestWhenOptionalTimeStampPassedThrough()
            throws URISyntaxException {
        var body =
                format(
                        "{ \"redirect-uri\": \"%s\", \"state\": \"%s\", \"claims\": [\"%s\"], \"rp-sector-uri\": \"%s\",  \"is-new-account\": \"%s\", \"password-reset-time\": \"%d\" }",
                        TEST_REDIRECT_URI,
                        TEST_STATE,
                        List.of("email-verified", "email"),
                        TEST_SECTOR_IDENTIFIER,
                        false,
                        PASSWORD_RESET_TIME);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        when(configurationService.getAuthCodeExpiry()).thenReturn(Long.valueOf(12));
        var userProfile = new UserProfile();
        userProfile.setSubjectID(TEST_SUBJECT_ID);
        when(authenticationService.getUserProfileFromEmail(CommonTestVariables.EMAIL))
                .thenReturn(Optional.of(userProfile));

        var result = handler.handleRequest(event, context);

        verify(dynamoAuthCodeService, times(1))
                .saveAuthCode(
                        eq(userProfile.getSubjectID()),
                        anyString(),
                        anyList(),
                        eq(false),
                        anyString(),
                        eq(false),
                        eq(PASSWORD_RESET_TIME),
                        eq(CLIENT_SESSION_ID));
        assertThat(result, hasStatus(200));
    }

    private APIGatewayProxyRequestEvent validAuthCodeRequest() {
        var body =
                format(
                        "{ \"redirect-uri\": \"%s\", \"state\": \"%s\", \"claims\": [\"%s\"], \"rp-sector-uri\": \"%s\",  \"is-new-account\": \"%s\" }",
                        TEST_REDIRECT_URI,
                        TEST_STATE,
                        List.of("email-verified", "email"),
                        TEST_SECTOR_IDENTIFIER,
                        false);
        return apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);
    }

    private UserProfile generateUserProfile() {
        return new UserProfile()
                .withEmail(CommonTestVariables.EMAIL)
                .withEmailVerified(true)
                .withPhoneNumberVerified(true)
                .withPublicSubjectID(new Subject().getValue())
                .withSubjectID(TEST_SUBJECT_ID);
    }
}
