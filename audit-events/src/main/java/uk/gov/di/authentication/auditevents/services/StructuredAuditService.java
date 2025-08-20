package uk.gov.di.authentication.auditevents.services;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.auditevents.entity.StructuredAuditEvent;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.ConfigurationService;

public class StructuredAuditService {
    private static final Logger LOG = LogManager.getLogger(StructuredAuditService.class);

    public static final String UNKNOWN = "";

    private final AwsSqsClient awsSqsClient;
    private final Gson gson;

    public StructuredAuditService(ConfigurationService configurationService) {
        this.awsSqsClient =
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getTxmaAuditQueueUrl(),
                        configurationService.getLocalstackEndpointUri());
        this.gson = createGson();
    }

    public StructuredAuditService(AwsSqsClient awsSqsClient) {
        this.awsSqsClient = awsSqsClient;
        this.gson = createGson();
    }

    private static Gson createGson() {
        return new GsonBuilder()
                .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
                .create();
    }

    public void submitAuditEvent(StructuredAuditEvent auditEvent) {
        LOG.info("Sending audit event to SQS: {}", auditEvent.eventName());

        String serializedEvent = serialize(auditEvent);
        awsSqsClient.send(serializedEvent);
    }

    private String serialize(StructuredAuditEvent auditEvent) {
        return gson.toJson(auditEvent);
    }
}
