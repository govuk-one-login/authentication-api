package uk.gov.di.authentication.auditevents.entity;

import com.google.gson.annotations.SerializedName;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.auditevents.entity.shared.EncodedDeviceInformation;
import uk.gov.di.authentication.auditevents.entity.shared.PasskeyWithCredentialId;
import uk.gov.di.authentication.auditevents.entity.shared.Users.UserWithoutPhone;
import uk.gov.di.authentication.shared.entity.JourneyType;

import java.time.Clock;
import java.time.Instant;

public record AuthPasskeyAuthenticationSuccessful(
        String eventName,
        long timestamp,
        long eventTimestampMs,
        String clientId,
        String componentId,
        UserWithoutPhone user,
        Restricted restricted,
        Extensions extensions)
        implements StructuredAuditEvent {

    public static AuthPasskeyAuthenticationSuccessful create(
            AuditContext auditContext,
            Passkey passkey,
            String passkeyCredentialId,
            JourneyType journeyType,
            Clock clock) {
        var eventName = "AUTH_PASSKEY_AUTHENTICATION_SUCCESSFUL";
        Instant now = clock.instant();
        var user = UserWithoutPhone.fromAuditContext(auditContext);
        var extensions = new Extensions(passkey, journeyType.getValue());
        var restricted =
                new Restricted(
                        new PasskeyWithCredentialId(passkeyCredentialId),
                        EncodedDeviceInformation.from(auditContext));
        return new AuthPasskeyAuthenticationSuccessful(
                eventName,
                now.getEpochSecond(),
                now.toEpochMilli(),
                auditContext.clientId(),
                ComponentId.AUTH.getValue(),
                user,
                restricted,
                extensions);
    }

    public record Passkey(
            int passkeyCounter,
            boolean passkeyCredentialBackedUp,
            String passkeyCredentialDeviceType,
            boolean passkeyUserVerified) {}

    public record Extensions(Passkey passkey, @SerializedName("journey-type") String journeyType) {}

    public record Restricted(
            PasskeyWithCredentialId passkey, EncodedDeviceInformation deviceInformation) {}
}
