package uk.gov.di.authentication.auditevents.entity;

import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.auditevents.entity.shared.RestrictedDeviceInformation;
import uk.gov.di.authentication.shared.helpers.PhoneNumberHelper;

import java.time.Clock;
import java.time.Instant;

public record AuthDeleteAccount(
        String eventName,
        long timestamp,
        long eventTimestampMs,
        String clientId,
        String componentId,
        User user,
        RestrictedDeviceInformation restricted,
        Extensions extensions)
        implements StructuredAuditEvent {

    private static final String EVENT_NAME = "AUTH_DELETE_ACCOUNT";

    public static AuthDeleteAccount create(
            AuditContext auditContext,
            String publicSubjectId,
            String legacySubjectId,
            String reason,
            Clock clock) {
        Instant now = clock.instant();
        var phoneNumberCountryCode =
                PhoneNumberHelper.maybeGetCountry(auditContext.phoneNumber()).orElse(null);
        return new AuthDeleteAccount(
                EVENT_NAME,
                now.getEpochSecond(),
                now.toEpochMilli(),
                auditContext.clientId(),
                ComponentId.AUTH.getValue(),
                new User(
                        auditContext.email(),
                        auditContext.clientSessionId(),
                        auditContext.ipAddress(),
                        legacySubjectId,
                        auditContext.persistentSessionId(),
                        auditContext.phoneNumber(),
                        publicSubjectId,
                        auditContext.sessionId(),
                        auditContext.subjectId()),
                RestrictedDeviceInformation.from(auditContext),
                new Extensions(reason, phoneNumberCountryCode));
    }

    public record User(
            String email,
            String govukSigninJourneyId,
            String ipAddress,
            String legacySubjectId,
            String persistentSessionId,
            String phone,
            String publicSubjectId,
            String sessionId,
            String userId) {}

    public record Extensions(String accountDeletionReason, String phoneNumberCountryCode) {}
}
