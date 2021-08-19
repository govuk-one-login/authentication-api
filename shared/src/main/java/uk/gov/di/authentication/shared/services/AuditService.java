package uk.gov.di.authentication.shared.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.domain.AuditableEvent;

public class AuditService {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuditService.class);

    public void submitAuditEvent(AuditableEvent event) {
        LOGGER.info("Emitting audit event - " + event);
    }
}
