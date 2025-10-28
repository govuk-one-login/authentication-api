package uk.gov.di.orchestration.audit;

import uk.gov.di.orchestration.shared.services.AuditService;

import java.util.List;

public record AuditContext(
        String clientSessionId,
        String sessionId,
        String clientId,
        String subjectId,
        String email,
        String ipAddress,
        String phoneNumber,
        String persistentSessionId,
        List<AuditService.MetadataPair> metadataPairs) {
    public AuditContext(
            String clientSessionId,
            String sessionId,
            String clientId,
            String subjectId,
            String email,
            String ipAddress,
            String phoneNumber,
            String persistentSessionId) {
        this(
                clientSessionId,
                sessionId,
                clientId,
                subjectId,
                email,
                ipAddress,
                phoneNumber,
                persistentSessionId,
                List.of());
    }
}
