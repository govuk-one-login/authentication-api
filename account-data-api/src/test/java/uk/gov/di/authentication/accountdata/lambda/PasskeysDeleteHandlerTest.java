package uk.gov.di.authentication.accountdata.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class PasskeysDeleteHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    private PasskeysDeleteHandler handler;

    @BeforeEach
    void setUp() {
        handler = new PasskeysDeleteHandler(configurationService);
    }

    @Test
    void shouldReturn204ForValidRequest() {
        var result = handler.handleRequest(passkeysDeleteRequest(), context);
        assertThat(result, hasStatus(204));
    }

    private APIGatewayProxyRequestEvent passkeysDeleteRequest() {
        return new APIGatewayProxyRequestEvent()
                .withHeaders(VALID_HEADERS)
                .withRequestContext(contextWithSourceIp(IP_ADDRESS));
    }
}
