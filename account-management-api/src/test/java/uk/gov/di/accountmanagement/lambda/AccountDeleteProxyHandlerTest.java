package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import uk.gov.di.authentication.auditevents.entity.AuthDeleteAccount;
import uk.gov.di.authentication.auditevents.entity.StructuredAuditEvent;
import uk.gov.di.authentication.auditevents.services.StructuredAuditService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountDataApiResponseException;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.AccountDataApiService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.PUBLIC_SUBJECT_ID;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AccountDeleteProxyHandlerTest {
    private final Context context = mock(Context.class);
    private final AccountDataApiService accountDataApiService = mock(AccountDataApiService.class);
    private final StructuredAuditService structuredAuditService =
            mock(StructuredAuditService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    private static final byte[] TEST_SALT = SaltHelper.generateNewSalt();
    private static final String TEST_SUBJECT = new Subject().getValue();
    private static final String TEST_LEGACY_SUBJECT = new Subject().getValue();

    private static final UserProfile userProfile =
            new UserProfile()
                    .withEmail(EMAIL)
                    .withPublicSubjectID(PUBLIC_SUBJECT_ID)
                    .withSubjectID(TEST_SUBJECT)
                    .withLegacySubjectID(TEST_LEGACY_SUBJECT);

    private AccountDeleteProxyHandler handler;

    private static final String ADAPI_TOKEN_HEADER = "X-ADAPI-AccessToken";
    private static final String TOKEN = "token";

    @BeforeEach
    void setUp() {
        when(configurationService.getInternalSectorUri()).thenReturn("https://test.account.gov.uk");
        when(dynamoService.getOptionalUserProfileFromPublicSubject(PUBLIC_SUBJECT_ID))
                .thenReturn(Optional.of(userProfile));
        when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(TEST_SALT);
        handler =
                new AccountDeleteProxyHandler(
                        configurationService,
                        accountDataApiService,
                        structuredAuditService,
                        dynamoService);
    }

    @Nested
    class ProxiedRequest {
        private static Stream<Arguments> accountDataApiResponses() {
            return Stream.of(
                    Arguments.of(204, ""),
                    Arguments.of(403, "{\"code\":4010,\"message\":\"Unauthorized request\"}"),
                    Arguments.of(404, "{\"code\":1056,\"message\":\"User not found or no match\"}"),
                    Arguments.of(500, "{\"code\":5000,\"message\":\"Internal server error\"}"));
        }

        @ParameterizedTest
        @MethodSource("accountDataApiResponses")
        void shouldReturnResponseFromService(int statusCode, String body)
                throws UnsuccessfulAccountDataApiResponseException {
            mockAccountDataApiResponse(PUBLIC_SUBJECT_ID, TOKEN, statusCode, body);

            var result =
                    handler.handleRequest(
                            accountDeleteProxyRequest(PUBLIC_SUBJECT_ID, TOKEN), context);

            assertThat(result, hasStatus(statusCode));
            assertThat(result, hasBody(body));
            verify(accountDataApiService).deleteAccount(PUBLIC_SUBJECT_ID, TOKEN);
        }

        @ParameterizedTest
        @MethodSource("accountDataApiResponses")
        void shouldEmitAccountDeleteAuditEventWhenResponseIs204(int statusCode, String body)
                throws UnsuccessfulAccountDataApiResponseException {
            mockAccountDataApiResponse(PUBLIC_SUBJECT_ID, TOKEN, statusCode, body);

            var result =
                    handler.handleRequest(
                            accountDeleteProxyRequest(PUBLIC_SUBJECT_ID, TOKEN), context);

            assertThat(result, hasStatus(statusCode));
            if (statusCode == 204) {
                var auditEventCaptor = ArgumentCaptor.forClass(AuthDeleteAccount.class);
                verify(structuredAuditService).submitAuditEvent(auditEventCaptor.capture());

                var auditEvent = auditEventCaptor.getValue();
                assertThat(auditEvent.eventName(), equalTo("AUTH_DELETE_ACCOUNT"));
                assertThat(auditEvent.user().email(), equalTo(EMAIL));
                assertThat(auditEvent.user().publicSubjectId(), equalTo(PUBLIC_SUBJECT_ID));
                assertThat(auditEvent.user().legacySubjectId(), equalTo(TEST_LEGACY_SUBJECT));
            } else {
                verify(structuredAuditService, never())
                        .submitAuditEvent(any(StructuredAuditEvent.class));
            }
        }

        @Test
        void shouldForwardRequestWithoutPublicSubjectId()
                throws UnsuccessfulAccountDataApiResponseException {
            var accountDataApiStatus = 400;
            mockAccountDataApiResponse("", TOKEN, accountDataApiStatus, "");

            var result = handler.handleRequest(accountDeleteProxyRequest(null, TOKEN), context);

            assertThat(result, hasStatus(accountDataApiStatus));
            verify(accountDataApiService).deleteAccount("", TOKEN);
        }

        @Test
        void shouldForwardRequestWithoutToken() throws UnsuccessfulAccountDataApiResponseException {
            var accountDataApiStatus = 401;
            mockAccountDataApiResponse(PUBLIC_SUBJECT_ID, "", accountDataApiStatus, "");

            var result =
                    handler.handleRequest(
                            accountDeleteProxyRequest(PUBLIC_SUBJECT_ID, null), context);

            assertThat(result, hasStatus(accountDataApiStatus));
            verify(accountDataApiService).deleteAccount(PUBLIC_SUBJECT_ID, "");
        }
    }

    @Nested
    class FailedRequest {
        @Test
        void shouldReturn500IfServiceThrowsException()
                throws UnsuccessfulAccountDataApiResponseException {
            when(accountDataApiService.deleteAccount(PUBLIC_SUBJECT_ID, TOKEN))
                    .thenThrow(new UnsuccessfulAccountDataApiResponseException("service error", 0));

            var result =
                    handler.handleRequest(
                            accountDeleteProxyRequest(PUBLIC_SUBJECT_ID, TOKEN), context);

            assertThat(result, hasStatus(500));
            assertThat(result, hasJsonBody(ErrorResponse.INTERNAL_SERVER_ERROR));
            verify(accountDataApiService).deleteAccount(PUBLIC_SUBJECT_ID, TOKEN);
        }
    }

    private void mockAccountDataApiResponse(
            String publicSubjectId, String token, int statusCode, String body)
            throws UnsuccessfulAccountDataApiResponseException {
        var mockHttpResponse = mock(HttpResponse.class);
        when(mockHttpResponse.statusCode()).thenReturn(statusCode);
        when(mockHttpResponse.body()).thenReturn(body);
        when(accountDataApiService.deleteAccount(publicSubjectId, token))
                .thenReturn(mockHttpResponse);
    }

    private APIGatewayProxyRequestEvent accountDeleteProxyRequest(
            String publicSubjectId, String token) {
        var headers = new HashMap<>(VALID_HEADERS);
        if (token != null) {
            headers.put(ADAPI_TOKEN_HEADER, token);
        }

        var pathParameters = new HashMap<String, String>();
        if (publicSubjectId != null) {
            pathParameters.put("publicSubjectId", publicSubjectId);
        }

        var requestContext = contextWithSourceIp(IP_ADDRESS);
        requestContext.setAuthorizer(Map.of("ClientId", "test-client-id"));

        return new APIGatewayProxyRequestEvent()
                .withPathParameters(pathParameters)
                .withHeaders(headers)
                .withBody("{\"clientId\":\"amc\",\"reason\":\"USER_INITIATED\"}")
                .withRequestContext(requestContext);
    }
}
