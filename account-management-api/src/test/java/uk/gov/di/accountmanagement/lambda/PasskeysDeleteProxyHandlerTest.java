package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class PasskeysDeleteProxyHandlerTest {
    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    private PasskeysDeleteProxyHandler handler;

    @BeforeEach
    void setUp() {
        handler = new PasskeysDeleteProxyHandler(configurationService);
    }

    @Test
    void shouldReturn501NotImplemented() {
        var result = handler.handleRequest(passkeysDeleteProxyRequest(), context);
        assertThat(result, hasStatus(501));
    }

    private APIGatewayProxyRequestEvent passkeysDeleteProxyRequest() {
        return new APIGatewayProxyRequestEvent()
                .withHeaders(VALID_HEADERS)
                .withRequestContext(contextWithSourceIp(IP_ADDRESS));
    }
}
