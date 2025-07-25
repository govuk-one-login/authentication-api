package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.ipv.services.IPVCapacityService;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.IPV_CAPACITY_REQUESTED;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachTraceId;

public class IPVCapacityHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(IPVCapacityHandler.class);
    private final IPVCapacityService capacityService;
    private final AuditService auditService;

    public IPVCapacityHandler() {
        this(ConfigurationService.getInstance());
    }

    public IPVCapacityHandler(IPVCapacityService capacityService, AuditService auditService) {
        this.capacityService = capacityService;
        this.auditService = auditService;
    }

    public IPVCapacityHandler(ConfigurationService configurationService) {
        this.capacityService = new IPVCapacityService(configurationService);
        this.auditService = new AuditService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        attachTraceId();
        LOG.info("Request received to IPVCapacityHandler");
        auditService.submitAuditEvent(
                IPV_CAPACITY_REQUESTED, AuditService.UNKNOWN, TxmaAuditUser.user());
        if (capacityService.isIPVCapacityAvailable()) {
            LOG.info("IPV Capacity available");
            return generateApiGatewayProxyResponse(200, "");
        } else {
            LOG.warn("IPV Capacity unavailable");
            return generateApiGatewayProxyResponse(503, "");
        }
    }
}
