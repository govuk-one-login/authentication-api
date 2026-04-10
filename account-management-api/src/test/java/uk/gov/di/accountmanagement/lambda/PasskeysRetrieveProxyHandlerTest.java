package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountDataApiResponseException;
import uk.gov.di.authentication.shared.services.AccountDataApiService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.net.http.HttpResponse;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.PUBLIC_SUBJECT_ID;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class PasskeysRetrieveProxyHandlerTest {
    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AccountDataApiService accountDataApiService = mock(AccountDataApiService.class);

    private PasskeysRetrieveProxyHandler handler;

    @BeforeEach
    void setUp() {
        handler = new PasskeysRetrieveProxyHandler(configurationService, accountDataApiService);
    }

    @Nested
    class SuccessfulRequest {
        @Test
        void shouldProxyResponseFromService() throws UnsuccessfulAccountDataApiResponseException {
            // Arrange
            var mockHttpResponse = mock(HttpResponse.class);
            when(mockHttpResponse.statusCode()).thenReturn(200);
            when(mockHttpResponse.body()).thenReturn("{\"passkeys\": []}");
            when(accountDataApiService.retrievePasskeys(PUBLIC_SUBJECT_ID))
                    .thenReturn(mockHttpResponse);

            // Act
            var result = handler.handleRequest(passkeysRetrieveProxyRequest(), context);

            // Assert
            assertThat(result, hasStatus(200));
            assertThat(result, hasBody("{\"passkeys\": []}"));
            verify(accountDataApiService).retrievePasskeys(PUBLIC_SUBJECT_ID);
        }
    }

    @Nested
    class FailedRequest {
        @Test
        void shouldReturn500IfServiceThrowsException()
                throws UnsuccessfulAccountDataApiResponseException {
            // Arrange
            when(accountDataApiService.retrievePasskeys(PUBLIC_SUBJECT_ID))
                    .thenThrow(new UnsuccessfulAccountDataApiResponseException("service error", 0));

            // Act
            var result = handler.handleRequest(passkeysRetrieveProxyRequest(), context);

            // Assert
            assertThat(result, hasStatus(500));
            assertThat(result, hasJsonBody(ErrorResponse.INTERNAL_SERVER_ERROR));
            verify(accountDataApiService).retrievePasskeys(PUBLIC_SUBJECT_ID);
        }
    }

    private APIGatewayProxyRequestEvent passkeysRetrieveProxyRequest() {
        return new APIGatewayProxyRequestEvent()
                .withPathParameters((Map.of("publicSubjectId", PUBLIC_SUBJECT_ID)))
                .withHeaders(VALID_HEADERS)
                .withRequestContext(contextWithSourceIp(IP_ADDRESS));
    }
}
