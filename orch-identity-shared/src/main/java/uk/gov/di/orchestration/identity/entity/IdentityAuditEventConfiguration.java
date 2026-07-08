package uk.gov.di.orchestration.identity.entity;

import uk.gov.di.orchestration.shared.domain.AuditableEvent;

public record IdentityAuditEventConfiguration(
        AuditableEvent authResponseReceived,
        AuditableEvent unsuccessfulTokenResponseReceived,
        AuditableEvent successfulTokenResponseReceived,
        AuditableEvent successfulIdentityResponseReceived,
        AuditableEvent spotRequested,
        AuditableEvent authCodeIssued) {}
