package uk.gov.di.authentication.auditevents.entity;

import com.google.gson.annotations.SerializedName;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.auditevents.entity.shared.RestrictedDeviceInformation;
import uk.gov.di.authentication.auditevents.entity.shared.Users.UserWithoutPhone;
import uk.gov.di.authentication.shared.entity.JourneyType;

import java.time.Clock;
import java.time.Instant;

public record AuthPasskeyRegistrationPromptSkipped(
        String eventName,
        long timestamp,
        long eventTimestampMs,
        String clientId,
        String componentId,
        UserWithoutPhone user,
        RestrictedDeviceInformation restricted,
        Extensions extensions)
        implements StructuredAuditEvent {

    public static AuthPasskeyRegistrationPromptSkipped create(
            AuditContext auditContext, JourneyType journeyType, Clock clock) {
        Instant now = clock.instant();
        return new AuthPasskeyRegistrationPromptSkipped(
                "AUTH_PASSKEY_REGISTRATION_PROMPT_SKIPPED",
                now.getEpochSecond(),
                now.toEpochMilli(),
                auditContext.clientId(),
                ComponentId.AUTH.getValue(),
                UserWithoutPhone.fromAuditContext(auditContext),
                RestrictedDeviceInformation.from(auditContext),
                new Extensions(journeyType.getValue()));
    }

    public record Extensions(@SerializedName("journey-type") String journeyType) {}
}
