package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.ipv.services.IPVCapacityService;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class IPVCapacityHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);

    private final AuditService auditService = mock(AuditService.class);
    private final IPVCapacityService ipvCapacityService = mock(IPVCapacityService.class);

    private IPVCapacityHandler handler;

    @BeforeEach
    void setup() {
        handler = new IPVCapacityHandler(configService, ipvCapacityService, auditService);
    }

    @Test
    void shouldReturn200WhenIPVCapacityAvailable() throws JsonProcessingException {
        when(ipvCapacityService.isIPVCapacityAvailable()).thenReturn(true);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        APIGatewayProxyResponseEvent response = makeHandlerRequest(event);

        assertThat(response, hasStatus(200));
    }

    @Test
    void shouldReturn503WhenIPVCapacityUnavailable() throws JsonProcessingException {
        when(ipvCapacityService.isIPVCapacityAvailable()).thenReturn(false);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        APIGatewayProxyResponseEvent response = makeHandlerRequest(event);

        assertThat(response, hasStatus(503));
    }

    private APIGatewayProxyResponseEvent makeHandlerRequest(APIGatewayProxyRequestEvent event) {
        var response = handler.handleRequest(event, context);

        return response;
    }
}
