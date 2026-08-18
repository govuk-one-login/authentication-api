package uk.gov.di.orchestration.sis.domain;

import uk.gov.di.orchestration.shared.domain.AuditableEvent;

public enum SISAuditableEvent implements AuditableEvent {
    ORCH_SIS_SUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED,
    ORCH_SIS_UNSUCCESSFUL_AUTHORISATION_RESPONSE_RECEIVED,
    ORCH_SIS_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
    ORCH_SIS_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
    ORCH_SIS_SUCCESSFUL_IDENTITY_RESPONSE_RECEIVED,
    AUTH_AUTH_CODE_ISSUED;

    @Override
    public AuditableEvent parseFromName(String name) {
        return valueOf(name);
    }
}
