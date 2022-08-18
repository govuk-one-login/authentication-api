package uk.gov.di.authentication.audit.lambda;

import org.apache.logging.log4j.message.ObjectMessage;
import uk.gov.di.audit.AuditPayload.AuditEvent;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.util.HashMap;

public class PerformanceAnalysisAuditLambda extends BaseAuditHandler {

    public PerformanceAnalysisAuditLambda(
            KmsConnectionService kmsConnectionService, ConfigurationService service) {
        super(kmsConnectionService, service);
    }

    public PerformanceAnalysisAuditLambda() {
        super();
    }

    @Override
    void handleAuditEvent(AuditEvent auditEvent) {
        var eventData = new HashMap<String, String>();

        eventData.put("event-id", auditEvent.getEventId());
        eventData.put("request-id", auditEvent.getRequestId());
        eventData.put("timestamp", auditEvent.getTimestamp());
        eventData.put("event-name", auditEvent.getEventName());
        eventData.put("client-id", auditEvent.getClientId());

        LOG.info(new ObjectMessage(eventData));
    }
}
