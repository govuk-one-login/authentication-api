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
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.entity.ReverificationResultRequest;
import uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables;
import uk.gov.di.authentication.frontendapi.services.ReverificationResultService;
import uk.gov.di.authentication.shared.entity.IDReverificationState;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulReverificationResponseException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.IDReverificationStateService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;

import static com.nimbusds.common.contenttype.ContentType.APPLICATION_JSON;
import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REVERIFY_SUCCESSFUL_TOKEN_RECEIVED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REVERIFY_VERIFICATION_INFO_RECEIVED;
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.CLIENT_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1058;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1059;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1061;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class ReverificationResultHandlerTest {
    private ReverificationResultHandler handler;
    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final ReverificationResultService reverificationResultService =
            mock(ReverificationResultService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final IDReverificationStateService idReverificationStateService =
            mock(IDReverificationStateService.class);
    private final String subjectId = "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
    private final Session session =
            new Session(SESSION_ID)
                    .setEmailAddress(EMAIL)
                    .setInternalCommonSubjectIdentifier(subjectId);
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
                    Optional.empty());

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(ReverificationResultHandler.class);

    private static final UserContext USER_CONTEXT = mock(UserContext.class);

    private static final String AUTHENTICATION_STATE = "abcdefg";
    private static final IDReverificationState ID_REVERIFICATION_STATE =
            new IDReverificationState()
                    .withAuthenticationState(AUTHENTICATION_STATE)
                    .withClientSessionId(CLIENT_SESSION_ID);

    @BeforeEach
    void setUp() throws URISyntaxException {
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
        when(USER_CONTEXT.getSession()).thenReturn(session);
        when(configurationService.getIPVBackendURI())
                .thenReturn(new URI("https://api.identity.account.gov.uk/token"));
        when(USER_CONTEXT.getSession()).thenReturn(session);
        when(USER_CONTEXT.getClientId()).thenReturn(CLIENT_ID);
        when(USER_CONTEXT.getClientSessionId()).thenReturn(CLIENT_SESSION_ID);
        var userProfile = mock(UserProfile.class);
        when(userProfile.getPhoneNumber()).thenReturn(CommonTestVariables.UK_MOBILE_NUMBER);
        when(USER_CONTEXT.getUserProfile()).thenReturn(Optional.of(userProfile));

        handler =
                new ReverificationResultHandler(
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        authenticationService,
                        reverificationResultService,
                        auditService,
                        idReverificationStateService);
    }

    @Nested
    class SuccessfulRequest {

        @BeforeEach
        void setUp() throws ParseException {
            when(idReverificationStateService.get(any()))
                    .thenReturn(Optional.ofNullable(ID_REVERIFICATION_STATE));
            when(reverificationResultService.getToken(any()))
                    .thenReturn(getSuccessfulTokenResponse());
        }

        @Test
        void shouldReturn200AndIPVResponseOnValidRequest()
                throws ParseException, UnsuccessfulReverificationResponseException {
            var userInfo =
                    successfulResponseWithBody(
                            "{ \"sub\": \"urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6\",\"success\": true}");

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
        }

        @Test
        void shouldSubmitSuccessfulTokenReceivedAuditEvent()
                throws ParseException, UnsuccessfulReverificationResponseException {
            var userInfo =
                    successfulResponseWithBody(
                            "{ \"sub\": \"urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6\",\"success\": true}");

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
        }

        @Test
        void shouldSubmitReverificationInfoAuditEventForReverificationSuccessResponse()
                throws ParseException, UnsuccessfulReverificationResponseException {
            var userInfo =
                    successfulResponseWithBody(
                            "{ \"sub\": \"urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6\",\"success\": true}");

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
                            AUTH_REVERIFY_VERIFICATION_INFO_RECEIVED,
                            auditContextWithAllUserInfo,
                            pair("journey-type", "ACCOUNT_RECOVERY"),
                            pair("success", true));
        }

        @Test
        void shouldSubmitReverificationInfoAuditEventForReverificationFailureResponse()
                throws ParseException, UnsuccessfulReverificationResponseException {
            var userInfo =
                    successfulResponseWithBody(
                            "{ \"sub\": \"urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6\",\"success\": false, \"failure_code\": \"no_identity_available\"}");
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
                            AUTH_REVERIFY_VERIFICATION_INFO_RECEIVED,
                            auditContextWithAllUserInfo,
                            pair("journey-type", "ACCOUNT_RECOVERY"),
                            pair("success", false),
                            pair("failure_code", "no_identity_available"));
        }

        @Test
        void shouldSubmitReverificationInfoAuditEventAndLogWarningWhenFailureCodeUnknown()
                throws ParseException, UnsuccessfulReverificationResponseException {
            var unknownFailureCode = "foo";
            var responseBody =
                    format(
                            "{ \"sub\": \"urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6\",\"success\": false, \"failure_code\": \"%s\"}",
                            unknownFailureCode);
            var userInfo = successfulResponseWithBody(responseBody);

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
                            AUTH_REVERIFY_VERIFICATION_INFO_RECEIVED,
                            auditContextWithAllUserInfo,
                            pair("journey-type", "ACCOUNT_RECOVERY"),
                            pair("success", false));

            assertThat(
                    logging.events(),
                    hasItem(
                            withMessageContaining(
                                    "Unknown ipv reverification failure code of foo")));
        }
    }

    @Nested
    class StateErrors {
        @Test
        void shouldHandleStateNotRecordedError() {
            when(idReverificationStateService.get(any())).thenReturn(Optional.empty());

            var result =
                    handler.handleRequest(
                            apiRequestEventWithEmail("1234", AUTHENTICATION_STATE, EMAIL), context);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ERROR_1061));
        }

        @Test
        void shouldHandleStateMismatchedClientSessionIdError() {
            when(idReverificationStateService.get(any()))
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
            when(idReverificationStateService.get(any()))
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
            when(idReverificationStateService.get(any()))
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

            when(idReverificationStateService.get(any()))
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
}
