package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.services.ReverificationResultService;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulReverificationResponseException;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static com.nimbusds.common.contenttype.ContentType.APPLICATION_JSON;
import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1058;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1059;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class ReverificationResultHandlerTest {
    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TEST_INTERNAL_COMMON_SUBJECT_ID = "test-internal-subject-id";
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
    private final Session session =
            new Session(SESSION_ID)
                    .setEmailAddress(EMAIL)
                    .setSessionId(TEST_SESSION_ID)
                    .setInternalCommonSubjectIdentifier(TEST_INTERNAL_COMMON_SUBJECT_ID);

    @BeforeEach
    void setUp() throws URISyntaxException {
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
        when(configurationService.getIPVBackendURI())
                .thenReturn(new URI("https://api.identity.account.gov.uk/token"));

        handler =
                new ReverificationResultHandler(
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        authenticationService,
                        reverificationResultService,
                        auditService);
    }

    @Test
    void shouldReturn200AndIPVResponseOnValidRequest()
            throws ParseException, UnsuccessfulReverificationResponseException {
        HTTPResponse userInfo = new HTTPResponse(200);
        userInfo.setContent(
                "{ \"sub\": \"urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6\",\"success\": true}");
        when(reverificationResultService.getToken(any())).thenReturn(getSuccessfulTokenResponse());
        when(reverificationResultService.sendIpvReverificationRequest(any())).thenReturn(userInfo);

        var result = handler.handleRequest(apiRequestEventWithEmail("1234", EMAIL), context);

        assertThat(result, hasStatus(200));
        assertThat(result, hasBody(userInfo.getContent()));
    }

    @Test
    void shouldHandleIPVTokenError()
            throws ParseException, UnsuccessfulReverificationResponseException {
        when(reverificationResultService.getToken(any()))
                .thenReturn(getUnsuccessfulTokenResponse());
        when(reverificationResultService.sendIpvReverificationRequest(any()))
                .thenThrow(
                        new UnsuccessfulReverificationResponseException(
                                "Error getting reverification result"));

        var result = handler.handleRequest(apiRequestEventWithEmail("1234", EMAIL), context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ERROR_1058));
    }

    @Test
    void shouldHandleIPVReverificationError()
            throws ParseException, UnsuccessfulReverificationResponseException {
        when(reverificationResultService.getToken(any())).thenReturn(getSuccessfulTokenResponse());
        when(reverificationResultService.sendIpvReverificationRequest(any()))
                .thenThrow(
                        new UnsuccessfulReverificationResponseException(
                                "Error getting reverification result"));

        var result = handler.handleRequest(apiRequestEventWithEmail("1234", EMAIL), context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ERROR_1059));
    }

    private Map<String, String> getHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", SESSION_ID);
        headers.put("di-persistent-session-id", DI_PERSISTENT_SESSION_ID);
        headers.put("X-Forwarded-For", IP_ADDRESS);
        return headers;
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

    private APIGatewayProxyRequestEvent apiRequestEventWithEmail(String code, String email) {
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(getHeaders());
        event.setBody(format("{ \"code\": \"%s\" , \"email\": \"%s\"}", code, email));
        return event;
    }
}
