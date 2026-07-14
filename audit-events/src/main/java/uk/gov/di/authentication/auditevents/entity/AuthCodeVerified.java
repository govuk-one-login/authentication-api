package uk.gov.di.authentication.auditevents.entity;

import com.google.gson.annotations.SerializedName;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.auditevents.entity.shared.RestrictedDeviceInformation;
import uk.gov.di.authentication.auditevents.entity.shared.Users.UserWithoutPhone;

import java.time.Clock;
import java.time.Instant;

public record AuthCodeVerified(
        String eventName,
        long timestamp,
        long eventTimestampMs,
        String clientId,
        String componentId,
        UserWithoutPhone user,
        RestrictedDeviceInformation restricted,
        Extensions extensions)
        implements StructuredAuditEvent {

    public static AuthCodeVerified create(
            AuditContext auditContext,
            String publicSubjectId,
            ComponentId componentId,
            Extensions extensions,
            Clock clock) {
        var eventName = "AUTH_CODE_VERIFIED";
        Instant now = clock.instant();
        var user = UserWithoutPhone.fromAuditContext(auditContext, publicSubjectId);
        var restricted = RestrictedDeviceInformation.from(auditContext);
        return new AuthCodeVerified(
                eventName,
                now.getEpochSecond(),
                now.toEpochMilli(),
                auditContext.clientId(),
                componentId.getValue(),
                user,
                restricted,
                extensions);
    }

    public record Extensions(
            @SerializedName("notification-type") String notificationType,
            @SerializedName("loginFailureCount") Integer loginFailureCount,
            @SerializedName("account-recovery") Object accountRecovery,
            @SerializedName("journey-type") String journeyType,
            @SerializedName("MFACodeEntered") String mfaCodeEntered,
            @SerializedName("mfa-type") String mfaType,
            @SerializedName("mfa-method") String mfaMethod) {}
}
