package uk.gov.di.orchestration.identity.testsupport;

import uk.gov.di.orchestration.shared.domain.AuditableEvent;

public enum TestAuditEvent implements AuditableEvent {
    TEST_AUTH_REQUEST_RECEIVED,
    TEST_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
    TEST_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
    TEST_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED,
    TEST_SPOT_REQUESTED,
    TEST_AUTH_CODE_ISSUED;

    @Override
    public AuditableEvent parseFromName(String name) {
        return valueOf(name);
    }
}
