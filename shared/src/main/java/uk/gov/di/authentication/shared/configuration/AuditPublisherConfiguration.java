package uk.gov.di.authentication.shared.configuration;

public interface AuditPublisherConfiguration {

    default String getAuditSigningKeyAlias() {
        return System.getenv("AUDIT_SIGNING_KEY_ALIAS");
    }

    default String getEventsSnsTopicArn() {
        return System.getenv("EVENTS_SNS_TOPIC_ARN");
    }
}
