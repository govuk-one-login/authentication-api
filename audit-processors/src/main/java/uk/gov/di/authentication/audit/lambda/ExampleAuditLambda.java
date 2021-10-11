package uk.gov.di.authentication.audit.lambda;

import uk.gov.di.audit.AuditPayload.AuditEvent;

public class ExampleAuditLambda extends BaseAuditHandler {

    @Override
    void handleAuditEvent(AuditEvent auditEvent) {
        LOG.info("Processing audit event with id: {}", auditEvent.getEventId());
    }
}
