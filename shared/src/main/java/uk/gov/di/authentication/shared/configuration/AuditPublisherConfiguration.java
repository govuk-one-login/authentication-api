package uk.gov.di.authentication.shared.configuration;

public interface AuditPublisherConfiguration extends BaseLambdaConfiguration {

    default String getAuditSigningKeyAlias() {
        return System.getenv("AUDIT_SIGNING_KEY_ALIAS");
    }

    default String getEventsSnsTopicArn() {
        return System.getenv("EVENTS_SNS_TOPIC_ARN");
    }

    default boolean isTxmaAuditEnabled() {
        return Boolean.parseBoolean(System.getenv("TXMA_AUDIT_ENABLED"));
    }

    default String getTxmaAuditQueueUrl() {
        return System.getenv("TXMA_AUDIT_QUEUE_URL");
    }
}
