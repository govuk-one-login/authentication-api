package uk.gov.di.authentication.audit.lambda;

import uk.gov.di.audit.AuditPayload.AuditEvent;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

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
        LOG.info("Hello, world!");
    }
}
