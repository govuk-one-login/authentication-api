package uk.gov.di.authentication.auditevents.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.auditevents.entity.StructuredAuditEvent;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.ConfigurationService;

public class StructuredAuditService {
    private static final Logger LOG = LogManager.getLogger(StructuredAuditService.class);

    public static final String UNKNOWN = "";

    private final AwsSqsClient awsSqsClient;

    public StructuredAuditService(ConfigurationService configurationService) {
        this.awsSqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getTxmaAuditQueueUrl(),
                        configurationService.getLocalstackEndpointUri());
    }

    public StructuredAuditService(AwsSqsClient awsSqsClient) {
        this.awsSqsClient = awsSqsClient;
    }

    public void submitAuditEvent(StructuredAuditEvent auditEvent) {
        LOG.info("Sending audit event to SQS: {}", auditEvent.eventName());

        String serializedEvent = auditEvent.serialize();
        awsSqsClient.send(serializedEvent);
    }
}
