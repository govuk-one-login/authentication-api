package uk.gov.di.authentication.auditevents.entity.shared.Users;

import uk.gov.di.audit.AuditContext;

public record UserWithoutPhone(
        String email,
        String govukSigninJourneyId,
        String ipAddress,
        String persistentSessionId,
        String sessionId,
        String userId,
        String publicSubjectId) {
    public static UserWithoutPhone fromAuditContext(AuditContext auditContext) {
        return new UserWithoutPhone(
                auditContext.email(),
                auditContext.clientSessionId(),
                auditContext.ipAddress(),
                auditContext.persistentSessionId(),
                auditContext.sessionId(),
                auditContext.subjectId(),
                null);
    }

    public static UserWithoutPhone fromAuditContext(
            AuditContext auditContext, String publicSubjectId) {
        return new UserWithoutPhone(
                auditContext.email(),
                auditContext.clientSessionId(),
                auditContext.ipAddress(),
                auditContext.persistentSessionId(),
                auditContext.sessionId(),
                auditContext.subjectId(),
                publicSubjectId);
    }
}
