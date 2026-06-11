package uk.gov.di.authentication.auditevents.entity.shared.Users;

import uk.gov.di.audit.AuditContext;

public record UserWithPasskeyCount(
        String email,
        String govukSigninJourneyId,
        String ipAddress,
        String persistentSessionId,
        String sessionId,
        String userId,
        int passkeyCount) {
    public static UserWithPasskeyCount from(AuditContext auditContext, int passkeyCount) {
        return new UserWithPasskeyCount(
                auditContext.email(),
                auditContext.clientSessionId(),
                auditContext.ipAddress(),
                auditContext.persistentSessionId(),
                auditContext.sessionId(),
                auditContext.subjectId(),
                passkeyCount);
    }
}
