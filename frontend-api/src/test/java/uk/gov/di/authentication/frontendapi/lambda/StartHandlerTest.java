package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.ClientStartInfo;
import uk.gov.di.authentication.frontendapi.entity.ReauthFailureReasons;
import uk.gov.di.authentication.frontendapi.entity.StartRequest;
import uk.gov.di.authentication.frontendapi.entity.StartResponse;
import uk.gov.di.authentication.frontendapi.entity.UserStartInfo;
import uk.gov.di.authentication.frontendapi.services.JarValidationService;
import uk.gov.di.authentication.frontendapi.services.StartService;
import uk.gov.di.authentication.shared.domain.CloudwatchMetrics;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.LevelOfConfidence;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.frontendapi.lambda.StartHandler.REAUTHENTICATE_HEADER;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.FAILURE_REASON;
import static uk.gov.di.authentication.shared.entity.CountType.ENTER_EMAIL;
import static uk.gov.di.authentication.shared.entity.CountType.ENTER_MFA_CODE;
import static uk.gov.di.authentication.shared.entity.CountType.ENTER_PASSWORD;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.CLIENT_NAME;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.shared.helpers.TxmaAuditHelper.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class StartHandlerTest {

    public static final String TEST_CLIENT_ID = "test_client_id";
    public static final String TEST_CLIENT_NAME = "test_client_name";
    private static final String TEST_SUBJECT_ID = "test_subject_id";
    private static final String TEST_RP_PAIRWISE_ID = "test_rp_pairwise_id";
    private static final String TEST_PREVIOUS_SIGN_IN_JOURNEY_ID = "test_journey_id";
    private static final String TEST_RP_SUBJECT_ID_HOST = "example.com";
    private static final int MAX_ALLOWED_RETRIES = 6;
    private static final String SESSION_ID = "session-id";
    public static final State STATE = new State();
    public static final URI REDIRECT_URL = URI.create("https://localhost/redirect");
    private static final Json objectMapper = SerializationService.getInstance();
    private static final String COOKIE_CONSENT = "accept";
    private static final Scope SCOPE = new Scope(OIDCScopeValue.OPENID.getValue());
    private static final String TEST_SUBJECT_TYPE = "pairwise";

    private StartHandler handler;
    private final Context context = mock(Context.class);
    private final AuditService auditService = mock(AuditService.class);
    private final StartService startService = mock(StartService.class);
    private final AuthenticationAttemptsService authenticationAttemptsService =
            mock(AuthenticationAttemptsService.class);
    private final UserProfile userProfile = mock(UserProfile.class);
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);
    private final UserContext userContext = mock(UserContext.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final JarValidationService jarValidationService = mock(JarValidationService.class);

    private static final AuditContext AUDIT_CONTEXT =
            new AuditContext(
                    TEST_CLIENT_ID,
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    AuditService.UNKNOWN,
                    AuditService.UNKNOWN,
                    IP_ADDRESS,
                    AuditService.UNKNOWN,
                    DI_PERSISTENT_SESSION_ID,
                    Optional.of(ENCODED_DEVICE_DETAILS),
                    new ArrayList<>());

    @BeforeEach
    void beforeEach() {
        when(configurationService.isIdentityEnabled()).thenReturn(true);
        when(configurationService.getEnvironment()).thenReturn("test");
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
        when(authSessionService.generateNewAuthSession(anyString())).thenCallRealMethod();
        handler =
                new StartHandler(
                        auditService,
                        startService,
                        authSessionService,
                        configurationService,
                        authenticationAttemptsService,
                        cloudwatchMetricsService,
                        jarValidationService);
    }

    private static Stream<Arguments> cookieConsentGaTrackingIdValues() {
        return Stream.of(
                Arguments.of(null, "some-ga-tracking-id"),
                Arguments.of("some-cookie-consent-value", null),
                Arguments.of(null, null),
                Arguments.of("some-cookie-consent-value", "some-ga-tracking-id"),
                Arguments.of(null, "some-ga-tracking-id"),
                Arguments.of("some-cookie-consent-value", null),
                Arguments.of(null, null),
                Arguments.of("some-cookie-consent-value", "some-ga-tracking-id"));
    }

    @ParameterizedTest
    @MethodSource("cookieConsentGaTrackingIdValues")
    void shouldReturn200WithStartResponse(String cookieConsentValue, String gaTrackingId)
            throws Json.JsonException {
        var userStartInfo = getUserStartInfo(cookieConsentValue, gaTrackingId);
        usingStartServiceThatReturns(userContext, getClientStartInfo(), userStartInfo);
        useValidSession();

        var event =
                apiRequestEventWithHeadersAndBody(
                        VALID_HEADERS, makeRequestBodyWithAuthenticatedField(false));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        StartResponse response = objectMapper.readValue(result.getBody(), StartResponse.class);

        assertThat(response.client(), equalTo(getClientStartInfo()));
        assertThat(response.user(), equalTo(userStartInfo));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_START_INFO_FOUND,
                        AUDIT_CONTEXT.withSubjectId(TEST_SUBJECT_ID),
                        pair("internalSubjectId", TEST_SUBJECT_ID));
    }

    @Test
    void shouldReturn200WithAuthenticatedFalseWhenAReauthenticationJourney()
            throws Json.JsonException {
        var isAuthenticated = false;
        var userStartInfo = new UserStartInfo(false, false, false, null, null, null, false);
        usingStartServiceThatReturns(userContext, getClientStartInfo(), userStartInfo);
        useValidSession();

        var body =
                makeRequestBody(
                        null,
                        TEST_PREVIOUS_SIGN_IN_JOURNEY_ID,
                        TEST_RP_PAIRWISE_ID,
                        isAuthenticated);
        var event = apiRequestEventWithHeadersAndBody(headersWithReauthenticate("true"), body);
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        var response = objectMapper.readValue(result.getBody(), StartResponse.class);

        assertFalse(response.user().isAuthenticated());

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_REAUTH_REQUESTED,
                        AUDIT_CONTEXT.withSubjectId(TEST_SUBJECT_ID),
                        pair("previous_govuk_signin_journey_id", TEST_PREVIOUS_SIGN_IN_JOURNEY_ID),
                        pair("rpPairwiseId", TEST_RP_PAIRWISE_ID));
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        CloudwatchMetrics.REAUTH_REQUESTED.getValue(),
                        Map.of(ENVIRONMENT.getValue(), configurationService.getEnvironment()));
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_START_INFO_FOUND,
                        AUDIT_CONTEXT.withSubjectId(TEST_SUBJECT_ID),
                        pair("internalSubjectId", TEST_SUBJECT_ID));
    }

    @Test
    void shouldNotCallAuthenticationAttemptsServiceWhenFeatureFlagIsOff()
            throws Json.JsonException {
        var isAuthenticated = false;
        when(configurationService.isAuthenticationAttemptsServiceEnabled()).thenReturn(false);
        var userStartInfo = new UserStartInfo(false, false, false, null, null, null, false);

        // This should not be called. Setup here is to ensure that the feature flag is determining
        // this test's behaviour
        when(authenticationAttemptsService.getCountsByJourneyForSubjectIdAndRpPairwiseId(
                        any(), any(), any()))
                .thenReturn(Map.of(CountType.ENTER_PASSWORD, 100));

        usingStartServiceThatReturns(userContext, getClientStartInfo(), userStartInfo);
        useValidSession();
        var body = makeRequestBody(null, null, TEST_RP_PAIRWISE_ID, isAuthenticated);
        var event = apiRequestEventWithHeadersAndBody(headersWithReauthenticate("true"), body);
        handler.handleRequest(event, context);

        verifyNoInteractions(authenticationAttemptsService);
    }

    @Test
    void shouldUseCountsAgainstTheRpPairwiseIdWhenThereIsNoSubjectId() throws Json.JsonException {
        var isAuthenticated = false;
        when(configurationService.isAuthenticationAttemptsServiceEnabled()).thenReturn(true);
        when(userProfile.getSubjectID()).thenReturn(null);

        var userStartInfo = new UserStartInfo(false, false, false, null, null, null, false);

        usingStartServiceThatReturns(userContext, getClientStartInfo(), userStartInfo);
        useValidSession();
        var body = makeRequestBody(null, null, TEST_RP_PAIRWISE_ID, isAuthenticated);
        var event = apiRequestEventWithHeadersAndBody(headersWithReauthenticate("true"), body);
        handler.handleRequest(event, context);

        verify(authenticationAttemptsService)
                .getCountsByJourney(TEST_RP_PAIRWISE_ID, JourneyType.REAUTHENTICATION);
    }

    @Test
    void checkAuditEventStillEmittedWhenTICFHeaderNotProvided() throws Json.JsonException {
        var isAuthenticated = false;
        var userStartInfo = new UserStartInfo(false, false, false, null, null, null, false);
        usingStartServiceThatReturns(userContext, getClientStartInfo(), userStartInfo);
        useValidSession();

        var headers = headersWithReauthenticate("true");
        headers.remove(TXMA_AUDIT_ENCODED_HEADER);
        var event =
                apiRequestEventWithHeadersAndBody(
                        headers, makeRequestBodyWithAuthenticatedField(isAuthenticated));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_REAUTH_REQUESTED,
                        AUDIT_CONTEXT
                                .withSubjectId(TEST_SUBJECT_ID)
                                .withTxmaAuditEncoded(Optional.empty()));
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        CloudwatchMetrics.REAUTH_REQUESTED.getValue(),
                        Map.of(ENVIRONMENT.getValue(), configurationService.getEnvironment()));
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_START_INFO_FOUND,
                        AUDIT_CONTEXT
                                .withSubjectId(TEST_SUBJECT_ID)
                                .withTxmaAuditEncoded(Optional.empty()),
                        pair("internalSubjectId", TEST_SUBJECT_ID));
    }

    @Test
    void shouldConsiderUserNotAuthenticatedWhenUserProfileNotPresent() throws Json.JsonException {
        withNoUserProfilePresent();
        var userStartInfo = new UserStartInfo(false, false, false, null, null, null, false);
        usingStartServiceThatReturns(userContext, getClientStartInfo(), userStartInfo);
        useValidSession();

        var event =
                apiRequestEventWithHeadersAndBody(
                        VALID_HEADERS, makeRequestBodyWithAuthenticatedField(true));

        handler.handleRequest(event, context);

        verify(startService)
                .buildUserStartInfo(
                        any(),
                        any(),
                        any(),
                        anyBoolean(),
                        anyBoolean(),
                        anyBoolean(),
                        eq(false),
                        anyBoolean());
    }

    @Test
    void considersUserAuthenticatedWhenUserProfilePresent() throws Json.JsonException {
        withUserProfilePresent();
        var userStartInfo = new UserStartInfo(false, false, true, null, null, null, false);
        usingStartServiceThatReturns(userContext, getClientStartInfo(), userStartInfo);
        useValidSession();

        var event =
                apiRequestEventWithHeadersAndBody(
                        VALID_HEADERS, makeRequestBodyWithAuthenticatedField(true));

        handler.handleRequest(event, context);

        verify(startService)
                .buildUserStartInfo(
                        any(),
                        any(),
                        any(),
                        anyBoolean(),
                        anyBoolean(),
                        anyBoolean(),
                        eq(true),
                        anyBoolean());
    }

    @Test
    void shouldReturn200WithAuthenticatedTrueWhenReauthenticateHeaderNotSetToTrue()
            throws Json.JsonException {
        withUserProfilePresent();
        var isAuthenticated = true;
        useValidSession();
        var userStartInfo =
                new UserStartInfo(false, false, isAuthenticated, null, null, null, false);
        usingStartServiceThatReturns(userContext, getClientStartInfo(), userStartInfo);

        var event =
                apiRequestEventWithHeadersAndBody(
                        headersWithReauthenticate("false"),
                        makeRequestBodyWithAuthenticatedField(isAuthenticated));
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        var response = objectMapper.readValue(result.getBody(), StartResponse.class);

        assertTrue(response.user().isAuthenticated());
        verify(auditService, never())
                .submitAuditEvent(
                        eq(FrontendAuditableEvent.AUTH_REAUTH_REQUESTED),
                        any(),
                        any(AuditService.MetadataPair[].class));
        verify(cloudwatchMetricsService, never())
                .incrementCounter(
                        CloudwatchMetrics.REAUTH_REQUESTED.getValue(),
                        Map.of(ENVIRONMENT.getValue(), configurationService.getEnvironment()));
    }

    private static Stream<Arguments> reauthCountTypesAndExpectedMetadata() {
        return Stream.of(
                Arguments.arguments(
                        ENTER_EMAIL,
                        MAX_ALLOWED_RETRIES,
                        0,
                        0,
                        ReauthFailureReasons.INCORRECT_EMAIL.getValue()),
                Arguments.arguments(
                        ENTER_PASSWORD,
                        0,
                        MAX_ALLOWED_RETRIES,
                        0,
                        ReauthFailureReasons.INCORRECT_PASSWORD.getValue()),
                Arguments.arguments(
                        ENTER_MFA_CODE,
                        0,
                        0,
                        MAX_ALLOWED_RETRIES,
                        ReauthFailureReasons.INCORRECT_OTP.getValue()));
    }

    @ParameterizedTest
    @MethodSource("reauthCountTypesAndExpectedMetadata")
    void shouldReturn200AndEmitReauthFailedEventWhenUserBlockedForReauthJourney(
            CountType countType,
            int expectedEmailAttemptCount,
            int expectedPasswordAttemptCount,
            int expectedOtpAttemptCount,
            String expectedFailureReason)
            throws Json.JsonException {
        var userStartInfo = new UserStartInfo(false, false, true, null, null, null, true);
        usingStartServiceThatReturns(userContext, getClientStartInfo(), userStartInfo);
        when(configurationService.isAuthenticationAttemptsServiceEnabled()).thenReturn(true);
        when(userContext.getUserProfile()).thenReturn(Optional.of(userProfile));
        when(userProfile.getSubjectID()).thenReturn(TEST_SUBJECT_ID);
        when(authenticationAttemptsService.getCountsByJourneyForSubjectIdAndRpPairwiseId(
                        any(), any(), eq(JourneyType.REAUTHENTICATION)))
                .thenReturn(Map.of(countType, MAX_ALLOWED_RETRIES));

        var isAuthenticated = true;
        useValidSession();

        var body = makeRequestBody(null, null, TEST_RP_PAIRWISE_ID, isAuthenticated);

        var event = apiRequestEventWithHeadersAndBody(headersWithReauthenticate("true"), body);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        verify(auditService, times(1))
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_REAUTH_FAILED,
                        AUDIT_CONTEXT.withSubjectId(TEST_SUBJECT_ID),
                        AuditService.MetadataPair.pair("rpPairwiseId", TEST_RP_PAIRWISE_ID),
                        AuditService.MetadataPair.pair(
                                "incorrect_email_attempt_count", expectedEmailAttemptCount),
                        AuditService.MetadataPair.pair(
                                "incorrect_password_attempt_count", expectedPasswordAttemptCount),
                        AuditService.MetadataPair.pair(
                                "incorrect_otp_code_attempt_count", expectedOtpAttemptCount),
                        AuditService.MetadataPair.pair("failure-reason", expectedFailureReason));
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        CloudwatchMetrics.REAUTH_FAILED.getValue(),
                        Map.of(
                                ENVIRONMENT.getValue(),
                                configurationService.getEnvironment(),
                                FAILURE_REASON.getValue(),
                                expectedFailureReason));
    }

    @Test
    void shouldInvokeJarValidationServiceWhenPassedJarRequest() throws Exception {
        var jarRequest = "test-jar-request";
        var clientId = "test-client-id";

        var userStartInfo = getUserStartInfo(null, null);
        usingStartServiceThatReturns(userContext, getClientStartInfo(), userStartInfo);
        useValidSession();
        when(configurationService.isJarValidationEnabled()).thenReturn(true);
        when(jarValidationService.parseAndValidateJar(anyString(), anyString()))
                .thenReturn(new JWTClaimsSet.Builder().build());

        var event =
                apiRequestEventWithHeadersAndBody(
                        VALID_HEADERS,
                        makeRequestBody(null, null, null, true, jarRequest, clientId));
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        verify(jarValidationService).parseAndValidateJar(jarRequest, clientId);
    }

    private String makeRequestBodyWithAuthenticatedField(boolean authenticated)
            throws Json.JsonException {
        return makeRequestBody(null, null, null, authenticated);
    }

    private void useValidSession() {
        when(authSessionService.getUpdatedPreviousSessionOrCreateNew(any(), any()))
                .thenReturn(
                        new AuthSessionItem()
                                .withSessionId(SESSION_ID)
                                .withClientId(CLIENT_ID)
                                .withInternalCommonSubjectId(TEST_SUBJECT_ID));
    }

    private ClientStartInfo getClientStartInfo() {
        return new ClientStartInfo(
                TEST_CLIENT_NAME,
                SCOPE.toStringList(),
                "MANDATORY",
                false,
                REDIRECT_URL,
                STATE,
                false);
    }

    private UserStartInfo getUserStartInfo(String cookieConsent, String gaCrossDomainTrackingId) {
        return new UserStartInfo(
                false, false, true, cookieConsent, gaCrossDomainTrackingId, null, false);
    }

    private void usingStartServiceThatReturns(
            UserContext userContext, ClientStartInfo clientStartInfo, UserStartInfo userStartInfo) {
        when(startService.buildUserContext(any(AuthSessionItem.class))).thenReturn(userContext);
        when(startService.buildClientStartInfo(
                        any(), any(), any(), any(), any(), anyBoolean(), anyBoolean()))
                .thenReturn(clientStartInfo);
        when(startService.buildUserStartInfo(
                        eq(userContext),
                        any(),
                        any(),
                        anyBoolean(),
                        anyBoolean(),
                        anyBoolean(),
                        anyBoolean(),
                        anyBoolean()))
                .thenReturn(userStartInfo);
    }

    private void withNoUserProfilePresent() {
        when(startService.isUserProfileEmpty(any(AuthSessionItem.class))).thenReturn(true);
    }

    private void withUserProfilePresent() {
        when(startService.isUserProfileEmpty(any(AuthSessionItem.class))).thenReturn(false);
    }

    private Map<String, String> headersWithReauthenticate(String reauthenticate) {
        Map<String, String> headers = new HashMap<>();
        headers.putAll(VALID_HEADERS);
        headers.put(REAUTHENTICATE_HEADER, reauthenticate);
        return headers;
    }

    private String makeRequestBody(
            String previousSessionId,
            String previousGovUkSignInJourneyId,
            String rpPairwiseIdForReauth,
            boolean authenticated)
            throws Json.JsonException {
        return makeRequestBody(
                previousSessionId,
                previousGovUkSignInJourneyId,
                rpPairwiseIdForReauth,
                authenticated,
                null,
                null);
    }

    private String makeRequestBody(
            String previousSessionId,
            String previousGovUkSignInJourneyId,
            String rpPairwiseIdForReauth,
            boolean authenticated,
            String jarRequest,
            String clientId)
            throws Json.JsonException {
        return objectMapper.writeValueAsString(
                new StartRequest(
                        previousSessionId,
                        rpPairwiseIdForReauth,
                        previousGovUkSignInJourneyId,
                        authenticated,
                        COOKIE_CONSENT,
                        null,
                        CredentialTrustLevel.MEDIUM_LEVEL.getValue(),
                        LevelOfConfidence.NONE.getValue(),
                        STATE.toString(),
                        TEST_CLIENT_ID,
                        REDIRECT_URL.toString(),
                        SCOPE.toString(),
                        CLIENT_NAME,
                        ServiceType.MANDATORY.toString(),
                        false,
                        false,
                        false,
                        TEST_SUBJECT_TYPE,
                        false,
                        TEST_RP_SUBJECT_ID_HOST,
                        clientId,
                        jarRequest));
    }
}
