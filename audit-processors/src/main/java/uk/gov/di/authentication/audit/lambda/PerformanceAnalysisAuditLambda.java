package uk.gov.di.authentication.audit.lambda;

import org.apache.logging.log4j.message.ObjectMessage;
import uk.gov.di.audit.AuditPayload.AuditEvent;
import uk.gov.di.audit.AuditPayload.AuditEvent.User;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.util.HashMap;

import static org.apache.commons.codec.binary.Hex.encodeHexString;
import static uk.gov.di.authentication.audit.helper.HmacSha256Helper.hmacSha256;

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
        eventData.put("session-id", auditEvent.getSessionId());
        eventData.put("timestamp", auditEvent.getTimestamp());
        eventData.put("event-name", auditEvent.getEventName());

        User user = auditEvent.getUser();

        var hmacKey = this.service.getAuditHmacSecret();

        if (user.getId() != null && !user.getId().isBlank()) {
            eventData.put("user-id", encodeHexString(hmacSha256(user.getId(), hmacKey)));
        }

        LOG.info(new ObjectMessage(eventData));
    }
}
