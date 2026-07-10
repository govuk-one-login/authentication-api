package uk.gov.di.authentication.auditevents.entity;

import uk.gov.di.audit.AuditContext;

import java.time.Clock;
import java.time.Instant;

public record AuthTokenSentToOrchestration(
        String eventName,
        long timestamp,
        long eventTimestampMs,
        String clientId,
        String componentId,
        User user)
        implements StructuredAuditEvent {

    public static AuthTokenSentToOrchestration create(
            AuditContext auditContext, String email, String publicSubjectId, Clock clock) {
        var eventName = "AUTH_TOKEN_SENT_TO_ORCHESTRATION";
        Instant now = clock.instant();
        var user = new User(auditContext.subjectId(), email, publicSubjectId);
        return new AuthTokenSentToOrchestration(
                eventName,
                now.getEpochSecond(),
                now.toEpochMilli(),
                auditContext.clientId(),
                ComponentId.AUTH.getValue(),
                user);
    }

    public record User(String userId, String email, String publicSubjectId) {}
}
