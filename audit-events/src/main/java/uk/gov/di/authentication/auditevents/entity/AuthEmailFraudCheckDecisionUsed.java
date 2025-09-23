package uk.gov.di.authentication.auditevents.entity;

import java.time.Instant;
import java.util.Objects;

public record AuthEmailFraudCheckDecisionUsed(
        String eventName,
        long timestamp,
        long eventTimestampMs,
        String clientId,
        String componentId,
        User user,
        Extensions extensions)
        implements StructuredAuditEvent {

    private static final String EVENT_NAME = "AUTH_EMAIL_FRAUD_CHECK_DECISION_USED";

    public AuthEmailFraudCheckDecisionUsed {
        Objects.requireNonNull(eventName);
        Objects.requireNonNull(componentId);
        Objects.requireNonNull(user);
        Objects.requireNonNull(extensions);
    }

    public static AuthEmailFraudCheckDecisionUsed create(
            String clientId, User user, Extensions extensions) {
        var now = Instant.now();
        return new AuthEmailFraudCheckDecisionUsed(
                EVENT_NAME,
                now.getEpochSecond(),
                now.toEpochMilli(),
                clientId,
                ComponentId.AUTH.getValue(),
                user,
                extensions);
    }

    public record User(
            String userId,
            String email,
            String ipAddress,
            String persistentSessionId,
            String govukSigninJourneyId) {
        public User {
            Objects.requireNonNull(email);
            Objects.requireNonNull(ipAddress);
            Objects.requireNonNull(persistentSessionId);
            Objects.requireNonNull(govukSigninJourneyId);
        }
    }

    public record Extensions(String journeyType, Object emailFraudCheckResponse) {
        public Extensions {
            Objects.requireNonNull(journeyType);
        }
    }
}
