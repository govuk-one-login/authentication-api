package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.oauth2.sdk.id.State;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCAuthorizationUrlAndCookie;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCAuthorizeRequest;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCAuthorizeResponse;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCFailureReason;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCJourneyType;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCScope;
import uk.gov.di.authentication.frontendapi.errormapper.AMCFailureHttpMapper;
import uk.gov.di.authentication.frontendapi.services.AMCService;
import uk.gov.di.authentication.shared.domain.CloudwatchMetrics;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAmcStateService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.sharedtest.helper.CommonTestVariables;

import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_AMC_AUTHORISATION_REQUESTED;
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.shared.entity.JourneyType.SIGN_IN;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.CLIENT_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.INTERNAL_COMMON_SUBJECT_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.PUBLIC_SUBJECT_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.sharedtest.helper.KeyPairHelper.GENERATE_RSA_KEY_PAIR;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class AMCAuthorizeHandlerTest {
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);
    private final JWKSource<SecurityContext> jwkSource = mock(JWKSource.class);
    private final AMCService amcService = mock(AMCService.class);
    private final DynamoAmcStateService dynamoAmcStateService = mock(DynamoAmcStateService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private AMCAuthorizeHandler handler;
    private final Context context = mock(Context.class);
    private final AuthSessionItem authSession =
            new AuthSessionItem()
                    .withSessionId(SESSION_ID)
                    .withInternalCommonSubjectId(INTERNAL_COMMON_SUBJECT_ID)
                    .withClientId(CLIENT_ID)
                    .withEmailAddress(EMAIL);
    private final UserProfile userProfile =
            new UserProfile().withEmail(EMAIL).withPublicSubjectID(PUBLIC_SUBJECT_ID);
    private final UserContext userContext = mock(UserContext.class);

    private static final String AMC_COOKIE = "some-cookie";
    private static final RSAKey TEST_RSA_JWK =
            new RSAKey.Builder((RSAPublicKey) GENERATE_RSA_KEY_PAIR().getPublic())
                    .keyID("test-encryption-key-id")
                    .build();
    private static final String ENV = "test";

    @BeforeEach
    void setUp() throws KeySourceException {
        handler =
                new AMCAuthorizeHandler(
                        configurationService,
                        authenticationService,
                        authSessionService,
                        amcService,
                        jwkSource,
                        dynamoAmcStateService,
                        auditService,
                        cloudwatchMetricsService);
        when(jwkSource.get(any(), any())).thenReturn(List.of(TEST_RSA_JWK));
        when(configurationService.getAMCSfadRedirectURI())
                .thenReturn("https://example.com/callback");
        when(configurationService.getAuthToAMApiAudience())
                .thenReturn("https://example.com/AmAudience");
        when(configurationService.getAMCCreatePasskeyRedirectURI())
                .thenReturn("https://example.com/account-data-callback");
        when(configurationService.getAuthToAccountDataApiAudience())
                .thenReturn("https://example.com/ADAPIAudience");
        when(configurationService.getEnvironment()).thenReturn(ENV);
        when(configurationService.getAMCSfadRedirectURI())
                .thenReturn("https://example.com/redirectUri");
        when(authSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(authSession));
        when(userContext.getAuthSession()).thenReturn(authSession);
        when(userContext.getClientSessionId()).thenReturn(CLIENT_SESSION_ID);
        when(userContext.getTxmaAuditEncoded()).thenReturn(AuditService.UNKNOWN);
    }

    @Nested
    class Success {
        private static final String REDIRECT_URL_RETURNED_FROM_AUTHORIZATION =
                "https://example.com/authorize";
        private static final APIGatewayProxyRequestEvent EVENT_WITH_VALID_HEADERS =
                new APIGatewayProxyRequestEvent()
                        .withHeaders(VALID_HEADERS)
                        .withRequestContext(contextWithSourceIp(IP_ADDRESS));

        @BeforeEach
        void setup() {
            when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                    .thenReturn(Optional.of(userProfile));

            var authorizationUrlAndCookie =
                    new AMCAuthorizationUrlAndCookie(
                            REDIRECT_URL_RETURNED_FROM_AUTHORIZATION, AMC_COOKIE);
            when(amcService.buildAuthorizationResult(
                            eq(INTERNAL_COMMON_SUBJECT_ID),
                            any(),
                            eq(authSession),
                            eq(PUBLIC_SUBJECT_ID),
                            anyString(),
                            anyList(),
                            any(RSAPublicKey.class),
                            anyString(),
                            any(State.class)))
                    .thenReturn(Result.success(authorizationUrlAndCookie));
        }

        @ParameterizedTest
        @MethodSource("amcJourneyTypeAndExpectedScope")
        void shouldReturnAuthorizationUrlAndAmcCookieOnSuccess(
                AMCJourneyType amcJourneyType, AMCScope expectedAmcScope) {
            var request = new AMCAuthorizeRequest(amcJourneyType);
            var result =
                    handler.handleRequestWithUserContext(
                            EVENT_WITH_VALID_HEADERS, context, request, userContext);

            var expectedResponse =
                    new AMCAuthorizeResponse(REDIRECT_URL_RETURNED_FROM_AUTHORIZATION, AMC_COOKIE);
            assertEquals(200, result.getStatusCode());
            assertThat(result, hasJsonBody(expectedResponse));
        }

        @ParameterizedTest
        @MethodSource("amcJourneyTypeAndExpectedScope")
        void shouldConstructTheAuthorizationResultWithTheCorrectTransportJwtAndTokenConfigs(
                AMCJourneyType amcJourneyType, AMCScope expectedAmcScope) {
            var request = new AMCAuthorizeRequest(amcJourneyType);
            var result =
                    handler.handleRequestWithUserContext(
                            EVENT_WITH_VALID_HEADERS, context, request, userContext);

            assertEquals(200, result.getStatusCode());

            var expectedRedirectUri =
                    request.amcJourneyType()
                            .getTransportJwtConfig(configurationService)
                            .redirectUri();
            var expectedAccessTokenConfigs =
                    request.amcJourneyType().getAccessTokenConfigs(configurationService);
            var stateCaptor = ArgumentCaptor.forClass(State.class);
            verify(amcService)
                    .buildAuthorizationResult(
                            eq(INTERNAL_COMMON_SUBJECT_ID),
                            eq(expectedAmcScope),
                            eq(authSession),
                            eq(PUBLIC_SUBJECT_ID),
                            eq(expectedRedirectUri),
                            eq(expectedAccessTokenConfigs),
                            any(RSAPublicKey.class),
                            anyString(),
                            stateCaptor.capture());
        }

        @ParameterizedTest
        @MethodSource("amcJourneyTypeAndExpectedScopeInAudtEvent")
        void shouldEmitTheRelevantAuditEventAndCloudwatchMetric(
                AMCJourneyType amcJourneyType, String expectedAmcScopeInAuditEvent) {
            var request = new AMCAuthorizeRequest(amcJourneyType);
            var result =
                    handler.handleRequestWithUserContext(
                            EVENT_WITH_VALID_HEADERS, context, request, userContext);

            assertEquals(200, result.getStatusCode());

            var expectedAuditContext =
                    AuditContext.emptyAuditContext()
                            .withClientId(CLIENT_ID)
                            .withClientSessionId(CLIENT_SESSION_ID)
                            .withSessionId(SESSION_ID)
                            .withSubjectId(INTERNAL_COMMON_SUBJECT_ID)
                            .withEmail(EMAIL)
                            .withIpAddress(IP_ADDRESS)
                            .withPersistentSessionId(DI_PERSISTENT_SESSION_ID);
            var expectedJourneyTypePair = pair("journey-type", SIGN_IN);
            var expectedAmcScopePair = pair("amc_scope", expectedAmcScopeInAuditEvent);
            verify(auditService)
                    .submitAuditEvent(
                            AUTH_AMC_AUTHORISATION_REQUESTED,
                            expectedAuditContext,
                            expectedJourneyTypePair,
                            expectedAmcScopePair);
            var expectedDimensions =
                    Map.ofEntries(
                            Map.entry("Environment", ENV),
                            Map.entry("AMCJourneyType", amcJourneyType.name()));
            verify(cloudwatchMetricsService)
                    .incrementCounter(
                            CloudwatchMetrics.AMC_AUTHORISATION_REQUESTED,
                            expectedDimensions);
        }

        private static Stream<Arguments> amcJourneyTypeAndExpectedScope() {
            return Stream.of(
                    Arguments.of(AMCJourneyType.SFAD, AMCScope.ACCOUNT_DELETE),
                    Arguments.of(AMCJourneyType.PASSKEY_CREATE, AMCScope.PASSKEY_CREATE));
        }

        private static Stream<Arguments> amcJourneyTypeAndExpectedScopeInAudtEvent() {
            return Stream.of(
                    Arguments.of(AMCJourneyType.SFAD, "sfad"),
                    Arguments.of(AMCJourneyType.PASSKEY_CREATE, "passkey-create"));
        }
    }

    @Nested
    class Failure {
        private static final APIGatewayProxyRequestEvent VALID_EVENT =
                apiRequestEventWithHeadersAndBody(
                        CommonTestVariables.VALID_HEADERS,
                        format("{\"journeyType\":\"%s\"}", AMCJourneyType.SFAD));

        @BeforeEach
        void setupUserProfile() {
            when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                    .thenReturn(Optional.of(userProfile));
        }

        @Test
        void shouldReturn400WhenUserProfileNotFound() {
            when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                    .thenReturn(Optional.empty());

            APIGatewayProxyResponseEvent result =
                    handler.handleRequestWithUserContext(
                            VALID_EVENT,
                            context,
                            new AMCAuthorizeRequest(AMCJourneyType.SFAD),
                            userContext);

            assertEquals(400, result.getStatusCode());
            assertTrue(
                    result.getBody()
                            .contains(ErrorResponse.EMAIL_HAS_NO_USER_PROFILE.getMessage()));
            verify(cloudwatchMetricsService, never()).incrementCounter(anyString(), anyMap());
        }

        @Test
        void shouldReturnJwksRetrievalErrorWhenKeySourceExceptionThrown()
                throws KeySourceException {
            when(jwkSource.get(any(), any()))
                    .thenThrow(new KeySourceException("JWKS endpoint unreachable"));

            APIGatewayProxyResponseEvent result =
                    handler.handleRequestWithUserContext(
                            VALID_EVENT,
                            context,
                            new AMCAuthorizeRequest(AMCJourneyType.SFAD),
                            userContext);

            var httpResponse =
                    AMCFailureHttpMapper.toHttpResponse(AMCFailureReason.JWKS_RETRIEVAL_ERROR);
            assertEquals(httpResponse.statusCode(), result.getStatusCode());
            assertTrue(result.getBody().contains(httpResponse.errorResponse().getMessage()));
            verify(auditService, never())
                    .submitAuditEvent(eq(AUTH_AMC_AUTHORISATION_REQUESTED), any());
            verify(cloudwatchMetricsService, never()).incrementCounter(anyString(), anyMap());
        }

        @Test
        void shouldReturnJwksRetrievalErrorWhenNoRsaKeyFound() throws KeySourceException {
            when(jwkSource.get(any(), any())).thenReturn(List.of());

            APIGatewayProxyResponseEvent result =
                    handler.handleRequestWithUserContext(
                            VALID_EVENT,
                            context,
                            new AMCAuthorizeRequest(AMCJourneyType.SFAD),
                            userContext);

            var httpResponse =
                    AMCFailureHttpMapper.toHttpResponse(AMCFailureReason.JWKS_RETRIEVAL_ERROR);
            assertEquals(httpResponse.statusCode(), result.getStatusCode());
            assertTrue(result.getBody().contains(httpResponse.errorResponse().getMessage()));
            verify(auditService, never())
                    .submitAuditEvent(eq(AUTH_AMC_AUTHORISATION_REQUESTED), any());
            verify(cloudwatchMetricsService, never()).incrementCounter(anyString(), anyMap());
        }

        @ParameterizedTest
        @EnumSource(AMCFailureReason.class)
        void shouldHandleAllFailureReasons(AMCFailureReason failureReason) {
            when(amcService.buildAuthorizationResult(
                            anyString(),
                            any(),
                            any(),
                            anyString(),
                            anyString(),
                            anyList(),
                            any(RSAPublicKey.class),
                            anyString(),
                            any()))
                    .thenReturn(Result.failure(failureReason));

            APIGatewayProxyResponseEvent result =
                    handler.handleRequestWithUserContext(
                            VALID_EVENT,
                            context,
                            new AMCAuthorizeRequest(AMCJourneyType.SFAD),
                            userContext);

            var expectedHttpResponse = AMCFailureHttpMapper.toHttpResponse(failureReason);
            var expectedError = expectedHttpResponse.errorResponse();

            assertEquals(expectedHttpResponse.statusCode(), result.getStatusCode());
            assertTrue(result.getBody().contains(expectedError.getMessage()));
            verify(auditService, never())
                    .submitAuditEvent(eq(AUTH_AMC_AUTHORISATION_REQUESTED), any());
            verify(cloudwatchMetricsService, never()).incrementCounter(anyString(), anyMap());
        }
    }
}
