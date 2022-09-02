package uk.gov.di.authentication.shared.configuration;

public interface AuditPublisherConfiguration extends BaseLambdaConfiguration {

    default String getTxmaAuditQueueUrl() {
        return System.getenv("TXMA_AUDIT_QUEUE_URL");
    }
}
