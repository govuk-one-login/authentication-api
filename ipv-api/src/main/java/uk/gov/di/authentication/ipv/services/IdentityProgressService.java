package uk.gov.di.authentication.ipv.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.ipv.domain.IPVAuditableEvent;
import uk.gov.di.authentication.ipv.entity.IdentityProgressStatus;
import uk.gov.di.orchestration.audit.AuditContext;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;

import java.util.Map;

import static uk.gov.di.authentication.ipv.utils.IdentityProgressUtils.getIdentityProgressStatus;

public class IdentityProgressService {

    private static final Logger LOG = LogManager.getLogger(IdentityProgressService.class);
    private static final int DELAY_IN_MS = 500;
    private static final int MAX_RETRIES = 10;
    private final ConfigurationService configurationService;
    private final DynamoIdentityService dynamoIdentityService;
    private final AuditService auditService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final Sleeper sleeper;

    public IdentityProgressService(ConfigurationService configurationService) {
        this(
                configurationService,
                new DynamoIdentityService(configurationService),
                new AuditService(configurationService),
                new CloudwatchMetricsService(configurationService),
                Thread::sleep);
    }

    public IdentityProgressService(
            ConfigurationService configurationService,
            DynamoIdentityService dynamoIdentityService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService,
            Sleeper sleeper) {
        this.configurationService = configurationService;
        this.dynamoIdentityService = dynamoIdentityService;
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.sleeper = sleeper;
    }

    public IdentityProgressStatus pollForStatus(String clientSessionId, AuditContext auditContext)
            throws InterruptedException {
        var status = IdentityProgressStatus.PROCESSING;
        var attempts = 1;
        while (status == IdentityProgressStatus.PROCESSING) {
            LOG.info("Attempting to find identity credentials in dynamo. Attempt: {}", attempts);
            var identityCredentials = dynamoIdentityService.getIdentityCredentials(clientSessionId);
            status = getIdentityProgressStatus(identityCredentials, attempts);
            if (status == IdentityProgressStatus.PROCESSING) {
                if (attempts >= MAX_RETRIES) {
                    LOG.info("Max retries of {} reached. Returning ERROR", MAX_RETRIES);
                    status = IdentityProgressStatus.ERROR;
                } else {
                    sleeper.sleep(DELAY_IN_MS);
                    attempts++;
                }
            }
        }
        LOG.info("Client session ID {} identity progress status: {}", clientSessionId, status);
        cloudwatchMetricsService.incrementCounter(
                "ProcessingIdentity",
                Map.of(
                        "Environment",
                        configurationService.getEnvironment(),
                        "Status",
                        status.toString()));
        auditService.submitAuditEvent(IPVAuditableEvent.PROCESSING_IDENTITY_REQUEST, auditContext);

        return status;
    }

    interface Sleeper {
        void sleep(long millis) throws InterruptedException;
    }
}
