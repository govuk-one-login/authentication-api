package uk.gov.di.audit;

public record AuditContext(
        String clientId,
        String clientSessionId,
        String sessionId,
        String subjectId,
        String email,
        String ipAddress,
        String phoneNumber,
        String persistentSessionId) {

    public AuditContext withPhoneNumber(String phoneNumber) {
        return new AuditContext(
                clientId,
                clientSessionId,
                sessionId,
                subjectId,
                email,
                ipAddress,
                phoneNumber,
                persistentSessionId);
    }

    public AuditContext withUserId(String subjectId) {
        return new AuditContext(
                clientId,
                clientSessionId,
                sessionId,
                subjectId,
                email,
                ipAddress,
                phoneNumber,
                persistentSessionId);
    }
}
