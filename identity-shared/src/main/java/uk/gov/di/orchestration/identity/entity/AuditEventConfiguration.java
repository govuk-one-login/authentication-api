package uk.gov.di.orchestration.identity.entity;

import uk.gov.di.orchestration.shared.domain.AuditableEvent;

public record AuditEventConfiguration(
        AuditableEvent unsuccessfulTokenResponseReceived,
        AuditableEvent successfulTokenResponseReceived) {}
