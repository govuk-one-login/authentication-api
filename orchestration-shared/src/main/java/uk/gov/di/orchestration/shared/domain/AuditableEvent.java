package uk.gov.di.orchestration.shared.domain;

public interface AuditableEvent {

    AuditableEvent parseFromName(String name);
}
