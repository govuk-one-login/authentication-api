package uk.gov.di.audit;

import java.util.Optional;

public record AuditContext(
        String clientId,
        String clientSessionId,
        String sessionId,
        String subjectId,
        String email,
        String ipAddress,
        String phoneNumber,
        String persistentSessionId,
        Optional<String> txmaAuditEncoded) {

    public AuditContext withPhoneNumber(String phoneNumber) {
        return new AuditContext(
                clientId,
                clientSessionId,
                sessionId,
                subjectId,
                email,
                ipAddress,
                phoneNumber,
                persistentSessionId,
                txmaAuditEncoded);
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
                persistentSessionId,
                txmaAuditEncoded);
    }

    public AuditContext withTxmaAuditEncoded(Optional<String> txmaAuditEncoded) {
        return new AuditContext(
                clientId,
                clientSessionId,
                sessionId,
                subjectId,
                email,
                ipAddress,
                phoneNumber,
                persistentSessionId,
                txmaAuditEncoded);
    }

    public AuditContext withSubjectId(String subjectId) {
        return new AuditContext(
                clientId,
                clientSessionId,
                sessionId,
                subjectId,
                email,
                ipAddress,
                phoneNumber,
                persistentSessionId,
                txmaAuditEncoded);
    }

    public AuditContext withEmail(String email) {
        return new AuditContext(
                clientId,
                clientSessionId,
                sessionId,
                subjectId,
                email,
                ipAddress,
                phoneNumber,
                persistentSessionId,
                txmaAuditEncoded);
    }
}
