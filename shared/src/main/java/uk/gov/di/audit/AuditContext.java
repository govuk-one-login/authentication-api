package uk.gov.di.audit;

public record AuditContext(
        String clientId,
        String clientSessionId,
        String sessionId,
        String subjectId,
        String email,
        String ipAddress,
        String phoneNumber,
        String persistentSessionId) {}
;
