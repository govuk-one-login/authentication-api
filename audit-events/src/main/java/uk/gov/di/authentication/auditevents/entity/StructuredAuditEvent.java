package uk.gov.di.authentication.auditevents.entity;

public interface StructuredAuditEvent {
    String eventName();

    long timestamp();

    long eventTimestampMs();

    String clientId();

    String componentId();
}
