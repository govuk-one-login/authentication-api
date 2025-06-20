package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.entity.ReverificationResultRequest;
import uk.gov.di.authentication.frontendapi.services.ReverificationResultService;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.IDReverificationState;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulReverificationResponseException;
import uk.gov.di.authentication.shared.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.IDReverificationStateService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Optional;
import java.util.stream.Stream;

import static com.nimbusds.common.contenttype.ContentType.APPLICATION_JSON;
import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REVERIFY_SUCCESSFUL_TOKEN_RECEIVED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REVERIFY_VERIFICATION_INFO_RECEIVED;
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1058;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1059;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1061;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class ReverificationResultHandlerTest {
    public static final String FAILED_REVERIFICATION_IPV_RESPONSE_TEMPLATE =
            """
                {
                    "sub": "%s",
                    "success": %s,
                    "failure_code": "%s",
                    "failure_reason": "%s"
                }
            """;
    public static final String SUCCESS_REVERIFICATION_IPV_RESPONSE_TEMPLATE =
            """
                {
                    "sub": "%s",
                    "success": %s
                }
            """;
    public static final String INVALID_RESPONSE_BASE_LOG_TEXT =
            "Invalid re-verification result response from IPV:";
    public static final String SUB = "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
    private ReverificationResultHandler handler;
    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final ReverificationResultService reverificationResultService =
            mock(ReverificationResultService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final IDReverificationStateService idReverificationStateService =
            mock(IDReverificationStateService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final String subjectId = "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
    private final AuditContext auditContextWithAllUserInfo =
            new AuditContext(
                    CLIENT_ID,
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    subjectId,
                    EMAIL,
                    IP_ADDRESS,
                    CommonTestVariables.UK_MOBILE_NUMBER,
                    DI_PERSISTENT_SESSION_ID,
                    Optional.empty(),
                    new ArrayList<>());

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(ReverificationResultHandler.class);

    private static final UserContext USER_CONTEXT = mock(UserContext.class);
    private final AuthSessionItem authSession =
            new AuthSessionItem()
                    .withSessionId(SESSION_ID)
                    .withInternalCommonSubjectId(SUB)
                    .withClientId(CLIENT_ID);

    private static final String AUTHENTICATION_STATE = "abcdefg";
    private static final IDReverificationState ID_REVERIFICATION_STATE =
            new IDReverificationState()
                    .withAuthenticationState(AUTHENTICATION_STATE)
                    .withClientSessionId(CLIENT_SESSION_ID);

    @BeforeEach
    void setUp() throws URISyntaxException {
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
        when(authSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(authSession));
        when(configurationService.getIPVBackendURI())
                .thenReturn(new URI("https://api.identity.account.gov.uk/token"));
        when(USER_CONTEXT.getAuthSession()).thenReturn(authSession);
        when(USER_CONTEXT.getClientSessionId()).thenReturn(CLIENT_SESSION_ID);
        var userProfile = mock(UserProfile.class);
        when(userProfile.getPhoneNumber()).thenReturn(CommonTestVariables.UK_MOBILE_NUMBER);
        when(USER_CONTEXT.getUserProfile()).thenReturn(Optional.of(userProfile));

        handler =
                new ReverificationResultHandler(
                        configurationService,
                        clientService,
                        authenticationService,
                        reverificationResultService,
                        auditService,
                        authSessionService,
                        idReverificationStateService,
                        cloudwatchMetricsService);
    }

    @Nested
    class SuccessfulRequest {

        @BeforeEach
        void setUp() throws ParseException {
            when(idReverificationStateService.get(anyString()))
                    .thenReturn(Optional.ofNullable(ID_REVERIFICATION_STATE));
            when(reverificationResultService.getToken(any()))
                    .thenReturn(getSuccessfulTokenResponse());
        }

        @Test
        void userPassesReverification()
                throws ParseException, UnsuccessfulReverificationResponseException {
            var userInfo =
                    successfulResponseWithBody(
                            SUCCESS_REVERIFICATION_IPV_RESPONSE_TEMPLATE.formatted(SUB, true));

            when(reverificationResultService.sendIpvReverificationRequest(any()))
                    .thenReturn(userInfo);

            ReverificationResultRequest request =
                    new ReverificationResultRequest("1234", AUTHENTICATION_STATE, EMAIL);

            var result =
                    handler.handleRequestWithUserContext(
                            apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}"),
                            context,
                            request,
                            USER_CONTEXT);

            verify(cloudwatchMetricsService).incrementMfaResetIpvResponseCount("success");

            assertThat(
                    logging.events(),
                    hasItem(withMessageContaining(format("Received reverification success code"))));
            assertThat(result, hasStatus(200));
            assertThat(result, hasBody(userInfo.getContent()));

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_REVERIFY_SUCCESSFUL_TOKEN_RECEIVED,
                            auditContextWithAllUserInfo,
                            pair("journey-type", "ACCOUNT_RECOVERY"));

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_REVERIFY_VERIFICATION_INFO_RECEIVED,
                            auditContextWithAllUserInfo,
                            pair("journey-type", "ACCOUNT_RECOVERY"),
                            pair("success", true));
        }

        @Test
        void userFailsReverification()
                throws ParseException, UnsuccessfulReverificationResponseException {
            var failedValidation =
                    FAILED_REVERIFICATION_IPV_RESPONSE_TEMPLATE.formatted(
                            SUB, false, "no_identity_available", "failure reason");
            var userInfo = successfulResponseWithBody(failedValidation);

            when(reverificationResultService.sendIpvReverificationRequest(any()))
                    .thenReturn(userInfo);

            ReverificationResultRequest request =
                    new ReverificationResultRequest("1234", AUTHENTICATION_STATE, EMAIL);

            var result =
                    handler.handleRequestWithUserContext(
                            apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}"),
                            context,
                            request,
                            USER_CONTEXT);

            assertThat(result, hasStatus(200));
            assertThat(result, hasBody(userInfo.getContent()));

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_REVERIFY_SUCCESSFUL_TOKEN_RECEIVED,
                            auditContextWithAllUserInfo,
                            pair("journey-type", "ACCOUNT_RECOVERY"));

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_REVERIFY_VERIFICATION_INFO_RECEIVED,
                            auditContextWithAllUserInfo,
                            pair("journey-type", "ACCOUNT_RECOVERY"),
                            pair("success", false),
                            pair("failure_code", "no_identity_available"));
        }

        @Test
        void reverificationResponseForDifferentUser()
                throws ParseException, UnsuccessfulReverificationResponseException {
            var failedValidation =
                    FAILED_REVERIFICATION_IPV_RESPONSE_TEMPLATE.formatted(
                            "other sub", false, "no_identity_available", "failure reason");
            var userInfo = successfulResponseWithBody(failedValidation);

            when(reverificationResultService.sendIpvReverificationRequest(any()))
                    .thenReturn(userInfo);

            ReverificationResultRequest request =
                    new ReverificationResultRequest("1234", AUTHENTICATION_STATE, EMAIL);

            var result =
                    handler.handleRequestWithUserContext(
                            apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}"),
                            context,
                            request,
                            USER_CONTEXT);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ERROR_1059));

            assertThat(
                    logging.events(),
                    hasItem(withMessageContaining("sub does not match current user.")));

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_REVERIFY_SUCCESSFUL_TOKEN_RECEIVED,
                            auditContextWithAllUserInfo,
                            pair("journey-type", "ACCOUNT_RECOVERY"));

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_REVERIFY_VERIFICATION_INFO_RECEIVED,
                            auditContextWithAllUserInfo,
                            pair("journey-type", "ACCOUNT_RECOVERY"));
        }

        @Test
        void reverificationResponseWithoutSubjectId()
                throws ParseException, UnsuccessfulReverificationResponseException {
            var missingSub =
                    """
                {
                    "success": true
                }
            """;
            var userInfo = successfulResponseWithBody(missingSub);

            when(reverificationResultService.sendIpvReverificationRequest(any()))
                    .thenReturn(userInfo);

            ReverificationResultRequest request =
                    new ReverificationResultRequest("1234", AUTHENTICATION_STATE, EMAIL);

            var result =
                    handler.handleRequestWithUserContext(
                            apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}"),
                            context,
                            request,
                            USER_CONTEXT);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ERROR_1059));

            assertThat(
                    logging.events(),
                    hasItem(
                            withMessageContaining(
                                    "Missing sub cannot verify response is for current user.")));

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_REVERIFY_SUCCESSFUL_TOKEN_RECEIVED,
                            auditContextWithAllUserInfo,
                            pair("journey-type", "ACCOUNT_RECOVERY"));

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_REVERIFY_VERIFICATION_INFO_RECEIVED,
                            auditContextWithAllUserInfo,
                            pair("journey-type", "ACCOUNT_RECOVERY"));
        }

        private static Stream<Arguments> scenariosWithFailureDetails() {
            return Stream.of(
                    Arguments.of(false, "foo", "failure_reason"),
                    Arguments.of(true, "no_identity_available", "failure reason"));
        }

        @ParameterizedTest
        @MethodSource("scenariosWithFailureDetails")
        void badReverificationResponse(boolean success, String failureCode, String failureReason)
                throws ParseException, UnsuccessfulReverificationResponseException {
            var semanticallyIncorrectResponse =
                    FAILED_REVERIFICATION_IPV_RESPONSE_TEMPLATE.formatted(
                            SUB, success, failureCode, failureReason);

            var userInfo = successfulResponseWithBody(semanticallyIncorrectResponse);

            when(reverificationResultService.sendIpvReverificationRequest(any()))
                    .thenReturn(userInfo);

            ReverificationResultRequest request =
                    new ReverificationResultRequest("1234", AUTHENTICATION_STATE, EMAIL);

            var result =
                    handler.handleRequestWithUserContext(
                            apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}"),
                            context,
                            request,
                            USER_CONTEXT);

            assertThat(result, hasStatus(400));

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_REVERIFY_SUCCESSFUL_TOKEN_RECEIVED,
                            auditContextWithAllUserInfo,
                            pair("journey-type", "ACCOUNT_RECOVERY"));

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_REVERIFY_VERIFICATION_INFO_RECEIVED,
                            auditContextWithAllUserInfo,
                            pair("journey-type", "ACCOUNT_RECOVERY"),
                            pair("success", success),
                            pair("failure_code", failureCode));

            if (success) {
                assertThat(
                        logging.events(),
                        hasItem(
                                withMessageContaining(
                                        INVALID_RESPONSE_BASE_LOG_TEXT,
                                        SUB,
                                        String.valueOf(failureCode),
                                        String.valueOf(failureReason),
                                        String.valueOf(true))));
            } else {
                assertThat(
                        logging.events(),
                        hasItem(
                                withMessageContaining(
                                        "ReverificationResult response received from IPV")));
            }
        }

        @Test
        void handleResponseMissingFailureCode()
                throws ParseException, UnsuccessfulReverificationResponseException {
            var sub = "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
            var success = false;
            var semanticallyIncorrectResponse =
                    SUCCESS_REVERIFICATION_IPV_RESPONSE_TEMPLATE.formatted(sub, success);

            var userInfo = successfulResponseWithBody(semanticallyIncorrectResponse);

            when(reverificationResultService.sendIpvReverificationRequest(any()))
                    .thenReturn(userInfo);

            ReverificationResultRequest request =
                    new ReverificationResultRequest("1234", AUTHENTICATION_STATE, EMAIL);

            handler.handleRequestWithUserContext(
                    apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{}"),
                    context,
                    request,
                    USER_CONTEXT);

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_REVERIFY_SUCCESSFUL_TOKEN_RECEIVED,
                            auditContextWithAllUserInfo,
                            pair("journey-type", "ACCOUNT_RECOVERY"));

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_REVERIFY_VERIFICATION_INFO_RECEIVED,
                            auditContextWithAllUserInfo,
                            pair("journey-type", "ACCOUNT_RECOVERY"),
                            pair("success", success));

            var expectLogMessage = "Invalid re-verification result response from IPV:";

            assertThat(
                    logging.events(),
                    hasItem(withMessageContaining(expectLogMessage, sub, String.valueOf(success))));
        }
    }

    @Nested
    class StateErrors {
        @Test
        void shouldHandleStateNotRecordedError() {
            when(idReverificationStateService.get(anyString())).thenReturn(Optional.empty());

            var result =
                    handler.handleRequest(
                            apiRequestEventWithEmail("1234", AUTHENTICATION_STATE, EMAIL), context);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ERROR_1061));
        }

        @Test
        void shouldHandleStateMismatchedClientSessionIdError() {
            when(idReverificationStateService.get(anyString()))
                    .thenReturn(
                            Optional.ofNullable(
                                    new IDReverificationState()
                                            .withAuthenticationState(AUTHENTICATION_STATE)
                                            .withClientSessionId("nonmatchingid")));

            var result =
                    handler.handleRequest(
                            apiRequestEventWithEmail("1234", AUTHENTICATION_STATE, EMAIL), context);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ERROR_1061));
        }
    }

    @Nested
    class TokenErrors {
        @Test
        void shouldHandleIPVTokenError()
                throws ParseException, UnsuccessfulReverificationResponseException {
            when(idReverificationStateService.get(anyString()))
                    .thenReturn(Optional.ofNullable(ID_REVERIFICATION_STATE));
            when(reverificationResultService.getToken(any()))
                    .thenReturn(getUnsuccessfulTokenResponse());
            when(reverificationResultService.sendIpvReverificationRequest(any()))
                    .thenThrow(
                            new UnsuccessfulReverificationResponseException(
                                    "Error getting reverification result"));

            var result =
                    handler.handleRequest(
                            apiRequestEventWithEmail("1234", AUTHENTICATION_STATE, EMAIL), context);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ERROR_1058));
        }
    }

    @Nested
    class ReverificationErrors {
        @Test
        void shouldHandleIPVReverificationError()
                throws ParseException, UnsuccessfulReverificationResponseException {
            when(idReverificationStateService.get(anyString()))
                    .thenReturn(Optional.ofNullable(ID_REVERIFICATION_STATE));
            when(reverificationResultService.getToken(any()))
                    .thenReturn(getSuccessfulTokenResponse());
            when(reverificationResultService.sendIpvReverificationRequest(any()))
                    .thenThrow(
                            new UnsuccessfulReverificationResponseException(
                                    "Error getting reverification result"));

            var result =
                    handler.handleRequest(
                            apiRequestEventWithEmail("1234", AUTHENTICATION_STATE, EMAIL), context);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ERROR_1059));
        }

        @ParameterizedTest
        @ValueSource(
                strings = {
                    "",
                    "{",
                    "{ \"sub\": \"urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6\"}"
                })
        void shouldReturnA400ForInvalidReverificationResponse(String responseContent)
                throws ParseException, UnsuccessfulReverificationResponseException {
            HTTPResponse userInfo = new HTTPResponse(200);
            userInfo.setContentType("application/json");
            userInfo.setContent(responseContent);

            when(idReverificationStateService.get(anyString()))
                    .thenReturn(Optional.ofNullable(ID_REVERIFICATION_STATE));
            when(reverificationResultService.getToken(any()))
                    .thenReturn(getSuccessfulTokenResponse());
            when(reverificationResultService.sendIpvReverificationRequest(any()))
                    .thenReturn(userInfo);

            var result =
                    handler.handleRequest(
                            apiRequestEventWithEmail("1234", AUTHENTICATION_STATE, EMAIL), context);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ERROR_1059));
        }
    }

    public TokenResponse getSuccessfulTokenResponse() throws ParseException {
        var tokenResponseContent =
                "{"
                        + "  \"access_token\": \"740e5834-3a29-46b4-9a6f-16142fde533a\","
                        + "  \"token_type\": \"bearer\","
                        + "  \"expires_in\": \"3600\""
                        + "}";
        var tokenHTTPResponse = new HTTPResponse(200);
        tokenHTTPResponse.setEntityContentType(APPLICATION_JSON);
        tokenHTTPResponse.setContent(tokenResponseContent);

        return TokenResponse.parse(tokenHTTPResponse);
    }

    private HTTPResponse successfulResponseWithBody(String body) throws ParseException {
        HTTPResponse userInfo = new HTTPResponse(200);
        userInfo.setContentType("application/json");
        userInfo.setContent(body);
        return userInfo;
    }

    public TokenResponse getUnsuccessfulTokenResponse() throws ParseException {
        var tokenResponseContent =
                "{"
                        + "\"error\": \"invalid_request\","
                        + "\"error_description\": \"Request was missing the 'redirect_uri' parameter.\""
                        + "}";

        var tokenHTTPResponse = new HTTPResponse(400);
        tokenHTTPResponse.setEntityContentType(APPLICATION_JSON);
        tokenHTTPResponse.setContent(tokenResponseContent);

        return TokenErrorResponse.parse(tokenHTTPResponse);
    }

    private APIGatewayProxyRequestEvent apiRequestEventWithEmail(
            String code, String state, String email) {
        var body =
                format(
                        "{ \"code\": \"%s\" , \"state\": \"%s\" , \"email\": \"%s\"}",
                        code, state, email);
        return apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);
    }

    @ParameterizedTest
    @MethodSource("ipvErrorResponses")
    void shouldIncrementMfaResetIpvResponseCountWhenErrorReturned(
            String responseContent, String failureCode)
            throws ParseException, UnsuccessfulReverificationResponseException {

        HTTPResponse userInfo = new HTTPResponse(200);
        userInfo.setContentType("application/json");
        userInfo.setContent(responseContent);

        when(idReverificationStateService.get(anyString()))
                .thenReturn(Optional.ofNullable(ID_REVERIFICATION_STATE));
        when(reverificationResultService.getToken(any())).thenReturn(getSuccessfulTokenResponse());
        when(reverificationResultService.sendIpvReverificationRequest(any())).thenReturn(userInfo);

        var result =
                handler.handleRequest(
                        apiRequestEventWithEmail("1234", AUTHENTICATION_STATE, EMAIL), context);

        verify(cloudwatchMetricsService).incrementMfaResetIpvResponseCount(failureCode);
        verify(cloudwatchMetricsService, never()).incrementMfaResetIpvResponseCount("success");

        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                format(
                                        "Received reverification failure code due to %s",
                                        failureCode))));
        assertThat(result, hasStatus(200));
    }

    static Stream<Arguments> ipvErrorResponses() {
        return Stream.of(
                Arguments.of(
                        "{ \"sub\": \"urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6\", \"success\": false, \"failure_code\": \"no_identity_available\", \"failure_description\": \"some failure description\"}",
                        "no_identity_available"),
                Arguments.of(
                        "{ \"sub\": \"urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6\", \"success\": false, \"failure_code\": \"identity_check_incomplete\", \"failure_description\": \"some failure description\"}",
                        "identity_check_incomplete"),
                Arguments.of(
                        "{ \"sub\": \"urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6\", \"success\": false, \"failure_code\": \"identity_check_failed\", \"failure_description\": \"some failure description\"}",
                        "identity_check_failed"),
                Arguments.of(
                        "{ \"sub\": \"urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6\", \"success\": false, \"failure_code\": \"identity_did_not_match\", \"failure_description\": \"some failure description\"}",
                        "identity_did_not_match"));
    }
}
