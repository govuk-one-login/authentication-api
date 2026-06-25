package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCCallbackRequest;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCFailureReason;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCScope;
import uk.gov.di.authentication.frontendapi.entity.amc.JourneyOutcomeError;
import uk.gov.di.authentication.frontendapi.services.AMCService;
import uk.gov.di.authentication.shared.entity.AMCState;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.helpers.LocaleHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAmcStateService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.io.IOException;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_AMC_AUTHORISATION_RECEIVED;
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.AMC_TOKEN_RESPONSE_ERROR;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.AMC_TOKEN_UNEXPECTED_ERROR;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.CLIENT_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.INTERNAL_COMMON_SUBJECT_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class AMCCallbackHandlerTest {
    private static final Context CONTEXT = mock(Context.class);
    private static final UserContext USER_CONTEXT = mock(UserContext.class);

    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);
    private static final AuthenticationService authenticationService =
            mock(AuthenticationService.class);
    private static final AuthSessionItem authSession =
            new AuthSessionItem()
                    .withSessionId(SESSION_ID)
                    .withClientId(CLIENT_ID)
                    .withEmailAddress(EMAIL)
                    .withInternalCommonSubjectId(INTERNAL_COMMON_SUBJECT_ID);
    private static final AuthSessionService authSessionService = mock(AuthSessionService.class);
    private static final DynamoAmcStateService dynamoAmcStateService =
            mock(DynamoAmcStateService.class);
    private static final AMCService AMC_SERVICE = mock(AMCService.class);
    private static final AuditService auditService = mock(AuditService.class);
    private static TokenRequest tokenRequest;
    private static AMCCallbackHandler handler;

    private static final String STATE = "state";
    private static final String AUTH_CODE = "1234";
    private static final String USED_REDIRECT_URL = "https://signin.account.gov.uk/amc-callback";
    private static final String ACCESS_TOKEN = "accessToken";
    private static final String SUCCESSFUL_TOKEN_RESPONSE =
            """
                    {
                        "access_token": "%s",
                        "token_type": "Bearer",
                        "expires_in": 3600
                    }
                    """
                    .formatted(ACCESS_TOKEN);
    private static final Date NOW = NowHelper.now();
    private static final AMCState AMC_STATE =
            new AMCState()
                    .withAuthenticationState(STATE)
                    .withClientSessionId(CLIENT_SESSION_ID)
                    .withTimeToExist(NOW.toInstant().plus(2L, ChronoUnit.HOURS).getEpochSecond());
    private static final AuditContext expectedAuditContext =
            new AuditContext(
                    CLIENT_ID,
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    INTERNAL_COMMON_SUBJECT_ID,
                    EMAIL,
                    IP_ADDRESS,
                    AuditService.UNKNOWN,
                    DI_PERSISTENT_SESSION_ID,
                    ENCODED_DEVICE_DETAILS);

    @BeforeAll
    static void setUp() {
        tokenRequest = mock(TokenRequest.class);
        when(configurationService.getAwsRegion()).thenReturn("eu-west-2");
        handler =
                new AMCCallbackHandler(
                        configurationService,
                        authenticationService,
                        authSessionService,
                        AMC_SERVICE,
                        dynamoAmcStateService,
                        auditService);
    }

    @BeforeEach
    void setup() {
        when(dynamoAmcStateService.getNonExpiredState(STATE)).thenReturn(Optional.of(AMC_STATE));
        when(USER_CONTEXT.getAuthSession()).thenReturn(authSession);
        when(USER_CONTEXT.getClientSessionId()).thenReturn(CLIENT_SESSION_ID);
        when(USER_CONTEXT.getTxmaAuditEncoded()).thenReturn(ENCODED_DEVICE_DETAILS);
        when(USER_CONTEXT.getUserLanguage()).thenReturn(LocaleHelper.SupportedLanguage.EN);
    }

    @AfterEach
    void resetMocks() {
        reset(AMC_SERVICE);
        reset(dynamoAmcStateService);
    }

    private static Stream<Arguments> scopeAndExpectedJourneyType() {
        return Stream.of(
                Arguments.of(AMCScope.ACCOUNT_DELETE, JourneyType.ACCOUNT_RECOVERY),
                Arguments.of(AMCScope.PASSKEY_CREATE, JourneyType.SIGN_IN));
    }

    @ParameterizedTest
    @MethodSource("scopeAndExpectedJourneyType")
    void shouldReturn200WhenTokenResponseSuccessful(AMCScope amcScope, JourneyType journeyType)
            throws IOException, ParseException {
        String journeyOutcomeResult = createJourneyOutcomeResultForAMCScope(amcScope);
        setupSuccessfulTokenResponse();
        setupJourneyOutcomeResponse(journeyOutcomeResult);
        AMCCallbackRequest request = new AMCCallbackRequest(AUTH_CODE, STATE, USED_REDIRECT_URL);

        APIGatewayProxyResponseEvent result =
                handler.handleRequestWithUserContext(
                        apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}"),
                        CONTEXT,
                        request,
                        USER_CONTEXT);

        assertEquals(200, result.getStatusCode());
        assertEquals(journeyOutcomeResult, result.getBody());

        verify(auditService)
                .submitAuditEvent(
                        AUTH_AMC_AUTHORISATION_RECEIVED,
                        expectedAuditContext,
                        pair("account_action_overall_outcome", true),
                        pair("account_actions", List.of(amcScope.getValue())),
                        pair("account_actions_errors", List.of()),
                        pair("account_actions_failed", List.of()),
                        pair("amc_scope", amcScope.getValue()),
                        pair("journey-type", journeyType));

        verify(dynamoAmcStateService).delete(STATE);
    }

    @Test
    void shouldTolerateANullTxmaEncodedValue() throws IOException, ParseException {
        when(USER_CONTEXT.getTxmaAuditEncoded()).thenReturn(AuditService.UNKNOWN);
        String journeyOutcomeResult =
                createJourneyOutcomeResultForAMCScope(AMCScope.ACCOUNT_DELETE);
        setupSuccessfulTokenResponse();
        setupJourneyOutcomeResponse(journeyOutcomeResult);
        AMCCallbackRequest request = new AMCCallbackRequest(AUTH_CODE, STATE, USED_REDIRECT_URL);

        APIGatewayProxyResponseEvent result =
                handler.handleRequestWithUserContext(
                        apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}"),
                        CONTEXT,
                        request,
                        USER_CONTEXT);

        assertEquals(200, result.getStatusCode());
        assertEquals(journeyOutcomeResult, result.getBody());
    }

    @Test
    void shouldReturn400WhenStateParamDoesNotExist() {
        when(dynamoAmcStateService.get(STATE)).thenReturn(Optional.empty());
        AMCCallbackRequest request =
                new AMCCallbackRequest(AUTH_CODE, "invalid-state", USED_REDIRECT_URL);

        APIGatewayProxyResponseEvent result =
                handler.handleRequestWithUserContext(
                        apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}"),
                        CONTEXT,
                        request,
                        USER_CONTEXT);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.AMC_STATE_MISMATCH));
    }

    @Test
    void shouldReturn400WhenStateParamBelongsToDifferentClientSessionId() {
        var stateWithDifferentClientSessionId =
                new AMCState()
                        .withAuthenticationState(STATE)
                        .withClientSessionId("another-clientSession");
        when(dynamoAmcStateService.getNonExpiredState(STATE))
                .thenReturn(Optional.of(stateWithDifferentClientSessionId));
        AMCCallbackRequest request = new AMCCallbackRequest(AUTH_CODE, STATE, USED_REDIRECT_URL);

        APIGatewayProxyResponseEvent result =
                handler.handleRequestWithUserContext(
                        apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}"),
                        CONTEXT,
                        request,
                        USER_CONTEXT);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.AMC_STATE_MISMATCH));

        verify(dynamoAmcStateService, never()).delete(STATE);
    }

    @Test
    void shouldReturn400WhenTokenResponseUnsuccessful() {
        when(AMC_SERVICE.buildTokenRequest(AUTH_CODE, USED_REDIRECT_URL))
                .thenReturn(Result.failure(AMCFailureReason.JWT_ENCODING_ERROR));

        AMCCallbackRequest request = new AMCCallbackRequest(AUTH_CODE, STATE, USED_REDIRECT_URL);

        APIGatewayProxyResponseEvent result =
                handler.handleRequestWithUserContext(
                        apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}"),
                        CONTEXT,
                        request,
                        USER_CONTEXT);

        assertEquals(400, result.getStatusCode());
    }

    @Test
    void shouldReturn500WhenErrorRetrievingToken() throws ParseException, IOException {
        HTTPRequest httpRequest = mock(HTTPRequest.class);
        when(AMC_SERVICE.buildTokenRequest(AUTH_CODE, USED_REDIRECT_URL))
                .thenReturn(Result.success(tokenRequest));
        when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);
        setupTokenHttpResponse(httpRequest, 500, "error from token response");

        AMCCallbackRequest request = new AMCCallbackRequest(AUTH_CODE, STATE, USED_REDIRECT_URL);

        APIGatewayProxyResponseEvent result =
                handler.handleRequestWithUserContext(
                        apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}"),
                        CONTEXT,
                        request,
                        USER_CONTEXT);

        assertEquals(500, result.getStatusCode());
        assertThat(result, hasJsonBody(AMC_TOKEN_RESPONSE_ERROR));
    }

    @Test
    void shouldReturn500WhenErrorResponseCannotBeParsedAsTokenResponse()
            throws ParseException, IOException {
        HTTPRequest httpRequest = mock(HTTPRequest.class);
        when(AMC_SERVICE.buildTokenRequest(AUTH_CODE, USED_REDIRECT_URL))
                .thenReturn(Result.success(tokenRequest));
        when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);
        setupTokenHttpResponse(httpRequest, 200, "{\"foo\": \"not a token response\"}");

        AMCCallbackRequest request = new AMCCallbackRequest(AUTH_CODE, STATE, USED_REDIRECT_URL);

        APIGatewayProxyResponseEvent result =
                handler.handleRequestWithUserContext(
                        apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}"),
                        CONTEXT,
                        request,
                        USER_CONTEXT);

        assertEquals(500, result.getStatusCode());
        assertThat(result, hasJsonBody(AMC_TOKEN_UNEXPECTED_ERROR));
    }

    @Test
    void shouldReturn500WhenIOExceptionCallingTokenEndpoint() throws IOException {
        HTTPRequest httpRequest = mock(HTTPRequest.class);
        when(AMC_SERVICE.buildTokenRequest(AUTH_CODE, USED_REDIRECT_URL))
                .thenReturn(Result.success(tokenRequest));
        when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);
        when(httpRequest.send()).thenThrow(new IOException("Uh oh"));

        AMCCallbackRequest request = new AMCCallbackRequest(AUTH_CODE, STATE, USED_REDIRECT_URL);

        APIGatewayProxyResponseEvent result =
                handler.handleRequestWithUserContext(
                        apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}"),
                        CONTEXT,
                        request,
                        USER_CONTEXT);

        assertEquals(500, result.getStatusCode());
        assertThat(result, hasJsonBody(AMC_TOKEN_UNEXPECTED_ERROR));
    }

    @Test
    void shouldReturn400WhenJourneyOutcomeResponseUnsuccessful()
            throws ParseException, IOException {
        HTTPRequest httpRequest = mock(HTTPRequest.class);
        when(AMC_SERVICE.buildTokenRequest(AUTH_CODE, USED_REDIRECT_URL))
                .thenReturn(Result.success(tokenRequest));
        when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);
        setupTokenHttpResponse(httpRequest, 200, SUCCESSFUL_TOKEN_RESPONSE);

        when(AMC_SERVICE.requestJourneyOutcome(
                        argThat(
                                userInfoRequest ->
                                        userInfoRequest
                                                .getAccessToken()
                                                .toString()
                                                .equals(ACCESS_TOKEN)),
                        any()))
                .thenReturn(
                        Result.failure(JourneyOutcomeError.ERROR_RESPONSE_FROM_JOURNEY_OUTCOME));

        AMCCallbackRequest request = new AMCCallbackRequest(AUTH_CODE, STATE, USED_REDIRECT_URL);

        APIGatewayProxyResponseEvent result =
                handler.handleRequestWithUserContext(
                        apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}"),
                        CONTEXT,
                        request,
                        USER_CONTEXT);

        assertEquals(400, result.getStatusCode());
    }

    @Test
    void shouldReturn500WhenJourneyOutcomeResponseGetsIOException()
            throws ParseException, IOException {
        HTTPRequest httpRequest = mock(HTTPRequest.class);
        when(AMC_SERVICE.buildTokenRequest(AUTH_CODE, USED_REDIRECT_URL))
                .thenReturn(Result.success(tokenRequest));
        when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);
        setupTokenHttpResponse(httpRequest, 200, SUCCESSFUL_TOKEN_RESPONSE);

        when(AMC_SERVICE.requestJourneyOutcome(
                        argThat(
                                userInfoRequest ->
                                        userInfoRequest
                                                .getAccessToken()
                                                .toString()
                                                .equals(ACCESS_TOKEN)),
                        any()))
                .thenReturn(Result.failure(JourneyOutcomeError.IO_EXCEPTION));

        AMCCallbackRequest request = new AMCCallbackRequest(AUTH_CODE, STATE, USED_REDIRECT_URL);

        APIGatewayProxyResponseEvent result =
                handler.handleRequestWithUserContext(
                        apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}"),
                        CONTEXT,
                        request,
                        USER_CONTEXT);

        assertEquals(500, result.getStatusCode());
    }

    @Test
    void shouldReturn500WhenJourneyOutcomeResponseFailsToParse()
            throws ParseException, IOException {
        setupSuccessfulTokenResponse();
        setupJourneyOutcomeResponse("not valid json");
        AMCCallbackRequest request = new AMCCallbackRequest(AUTH_CODE, STATE, USED_REDIRECT_URL);

        APIGatewayProxyResponseEvent result =
                handler.handleRequestWithUserContext(
                        apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}"),
                        CONTEXT,
                        request,
                        USER_CONTEXT);

        assertEquals(500, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.AMC_JOURNEY_OUTCOME_UNEXPECTED_ERROR));
        verify(auditService, never()).submitAuditEvent(any(), any(), any());
    }

    @Test
    void shouldEmitAuditEventWithFailedActionsAndErrors() throws IOException, ParseException {
        var failedJourneyOutcome =
                """
                        {
                          "outcome_id": "8bc3d34e7e22bbdc88beaa37283d0ace4d80e5d1505aa30",
                          "sub": "urn:fdc:gov.uk:2022:JG0RJI1pYbnanbvPs-j4j5-a-PFcmhry9Qu9NCEp5d4",
                          "email": "user@example.com",
                          "scope": "passkey-create",
                          "success": false,
                          "actions": [
                            {
                              "action": "passkey-create",
                              "timestamp": 1760718467000,
                              "success": false,
                              "details": {
                                "error": {
                                  "code": 1003,
                                  "description": "UserBackedOutOfJourney"
                                }
                              }
                            }
                          ]
                        }
                        """;
        setupSuccessfulTokenResponse();
        setupJourneyOutcomeResponse(failedJourneyOutcome);
        AMCCallbackRequest request = new AMCCallbackRequest(AUTH_CODE, STATE, USED_REDIRECT_URL);

        APIGatewayProxyResponseEvent result =
                handler.handleRequestWithUserContext(
                        apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}"),
                        CONTEXT,
                        request,
                        USER_CONTEXT);

        assertEquals(200, result.getStatusCode());

        verify(auditService)
                .submitAuditEvent(
                        AUTH_AMC_AUTHORISATION_RECEIVED,
                        expectedAuditContext,
                        pair("account_action_overall_outcome", false),
                        pair("account_actions", List.of("passkey-create")),
                        pair("account_actions_errors", List.of("UserBackedOutOfJourney")),
                        pair("account_actions_failed", List.of("passkey-create")),
                        pair("amc_scope", "passkey-create"),
                        pair("journey-type", JourneyType.SIGN_IN));
    }

    private void setupSuccessfulTokenResponse() throws IOException, ParseException {
        HTTPRequest httpRequest = mock(HTTPRequest.class);
        when(AMC_SERVICE.buildTokenRequest(AUTH_CODE, USED_REDIRECT_URL))
                .thenReturn(Result.success(tokenRequest));
        when(tokenRequest.toHTTPRequest()).thenReturn(httpRequest);
        setupTokenHttpResponse(httpRequest, 200, SUCCESSFUL_TOKEN_RESPONSE);
    }

    private void setupJourneyOutcomeResponse(String journeyOutcomeContent) {
        var journeyOutcomeHttpResponse = new HTTPResponse(200);
        journeyOutcomeHttpResponse.setBody(journeyOutcomeContent);

        when(AMC_SERVICE.requestJourneyOutcome(
                        argThat(
                                userInfoRequest ->
                                        userInfoRequest
                                                .getAccessToken()
                                                .toString()
                                                .equals(ACCESS_TOKEN)),
                        any()))
                .thenReturn(Result.success(journeyOutcomeHttpResponse));
    }

    private void setupTokenHttpResponse(
            HTTPRequest httpRequest, int tokenResponseCode, String tokenResponseBody)
            throws ParseException, IOException {
        var httpResponse = new HTTPResponse(tokenResponseCode);
        httpResponse.setContentType("application/json");
        httpResponse.setBody(tokenResponseBody);
        when(httpRequest.send()).thenReturn(httpResponse);
    }

    private String createJourneyOutcomeResultForAMCScope(AMCScope amcScope) {
        return """
                            {
                              "outcome_id": "9cd4c45f8f33cced99cfaa48394e1acf5e90f6e2616bba40",
                              "sub": "urn:fdc:gov.uk:2022:JG0RJI1pYbnanbvPs-j4j5-a-PFcmhry9Qu9NCEp5d4",
                              "email": "user@example.com",
                              "scope": "%s",
                              "success": true,
                              "actions": [
                                {
                                  "action": "%s",
                                  "timestamp": 1760718467000,
                                  "success": true,
                                  "details": {}
                                }
                              ]
                            }
                    """
                .formatted(amcScope.getValue(), amcScope.getValue());
    }
}
