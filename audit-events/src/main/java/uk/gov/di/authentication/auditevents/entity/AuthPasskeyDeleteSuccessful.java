package uk.gov.di.authentication.auditevents.entity;

import com.google.gson.annotations.SerializedName;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.auditevents.entity.shared.EncodedDeviceInformation;
import uk.gov.di.authentication.auditevents.entity.shared.PasskeyWithCredentialId;
import uk.gov.di.authentication.auditevents.entity.shared.Users.UserWithPasskeyCount;
import uk.gov.di.authentication.shared.entity.JourneyType;

import java.time.Clock;
import java.time.Instant;

public record AuthPasskeyDeleteSuccessful(
        String eventName,
        long timestamp,
        long eventTimestampMs,
        String clientId,
        String componentId,
        UserWithPasskeyCount user,
        Restricted restricted,
        Extensions extensions)
        implements StructuredAuditEvent {

    public static AuthPasskeyDeleteSuccessful create(
            AuditContext auditContext, int passkeyCount, String deletedCredentialId, Clock clock) {
        Instant now = clock.instant();
        var user = UserWithPasskeyCount.from(auditContext, passkeyCount);
        var restrictedSection =
                new Restricted(
                        EncodedDeviceInformation.from(auditContext),
                        new PasskeyWithCredentialId(deletedCredentialId));
        var extensions = new Extensions(JourneyType.ACCOUNT_MANAGEMENT.getValue());
        return new AuthPasskeyDeleteSuccessful(
                "AUTH_PASSKEY_DELETE_SUCCESSFUL",
                now.getEpochSecond(),
                now.toEpochMilli(),
                auditContext.clientId(),
                ComponentId.HOME.getValue(),
                user,
                restrictedSection,
                extensions);
    }

    public record Restricted(
            EncodedDeviceInformation deviceInformation, PasskeyWithCredentialId passkey) {}

    public record Extensions(@SerializedName("journey-type") String journeyType) {}
}
