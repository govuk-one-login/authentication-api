package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.ipv.services.IPVCapacityService;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.services.AuditService;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.IPV_CAPACITY_REQUESTED;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class IPVCapacityHandlerTest {

    private final Context context = mock(Context.class);

    private final AuditService auditService = mock(AuditService.class);
    private final IPVCapacityService ipvCapacityService = mock(IPVCapacityService.class);

    private IPVCapacityHandler handler;

    @BeforeEach
    void setup() {
        handler = new IPVCapacityHandler(ipvCapacityService, auditService);
    }

    @Test
    void shouldReturn200WhenIPVCapacityAvailable() {
        when(ipvCapacityService.isIPVCapacityAvailable()).thenReturn(true);

        var response = handler.handleRequest(new APIGatewayProxyRequestEvent(), context);

        assertThat(response, hasStatus(200));
        verify(auditService).submitAuditEvent(IPV_CAPACITY_REQUESTED, "", TxmaAuditUser.user());
    }

    @Test
    void shouldReturn503WhenIPVCapacityUnavailable() {
        when(ipvCapacityService.isIPVCapacityAvailable()).thenReturn(false);

        var response = handler.handleRequest(new APIGatewayProxyRequestEvent(), context);

        assertThat(response, hasStatus(503));
        verify(auditService).submitAuditEvent(IPV_CAPACITY_REQUESTED, "", TxmaAuditUser.user());
    }
}
