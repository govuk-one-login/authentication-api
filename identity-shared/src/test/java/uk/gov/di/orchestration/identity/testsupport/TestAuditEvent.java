package uk.gov.di.orchestration.identity.testsupport;

import uk.gov.di.orchestration.shared.domain.AuditableEvent;

public enum TestAuditEvent implements AuditableEvent {
    TEST_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
    TEST_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
    TEST_PROCESSING_IDENTITY_REQUEST;

    @Override
    public AuditableEvent parseFromName(String name) {
        return valueOf(name);
    }
}
