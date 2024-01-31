package uk.gov.di.orchestration.audit;

import uk.gov.di.orchestration.shared.services.AuditService;

public record AuditContext(
        String clientSessionId,
        String sessionId,
        String clientId,
        String subjectId,
        String email,
        String ipAddress,
        String phoneNumber,
        String persistentSessionId,
        AuditService.MetadataPair... metadataPairs) {}
