package uk.gov.di.authentication.oidc.domain;

import uk.gov.di.orchestration.shared.domain.AuditableEvent;

public enum OrchestrationAuditableEvent implements AuditableEvent {
    AUTH_CALLBACK_RESPONSE_RECEIVED,
    AUTH_UNSUCCESSFUL_CALLBACK_RESPONSE_RECEIVED,
    AUTH_SUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
    AUTH_UNSUCCESSFUL_TOKEN_RESPONSE_RECEIVED,
    AUTH_SUCCESSFUL_USERINFO_RESPONSE_RECEIVED,
    AUTH_UNSUCCESSFUL_USERINFO_RESPONSE_RECEIVED;

    @Override
    public AuditableEvent parseFromName(String name) {
        return valueOf(name);
    }
}
