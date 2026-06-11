package uk.gov.di.authentication.auditevents.entity;

import com.google.gson.annotations.SerializedName;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.auditevents.entity.shared.EncodedDeviceInformation;
import uk.gov.di.authentication.auditevents.entity.shared.Users.UserWithoutPhone;
import uk.gov.di.authentication.auditevents.entity.shared.passkeys.PasskeyAllowCredentials;
import uk.gov.di.authentication.auditevents.entity.shared.passkeys.PasskeyAuthenticationRequest;
import uk.gov.di.authentication.shared.entity.JourneyType;

import java.time.Clock;
import java.time.Instant;
import java.util.List;

public record AuthPasskeyVerificationFailed(
        String eventName,
        long timestamp,
        long eventTimestampMs,
        String clientId,
        String componentId,
        UserWithoutPhone user,
        Restricted restricted,
        Extensions extensions)
        implements StructuredAuditEvent {

    public static AuthPasskeyVerificationFailed create(
            AuditContext auditContext,
            JourneyType journeyType,
            List<PasskeyAllowCredentials> passkeyAllowCredentials,
            String passkeyCredentialId,
            PasskeyVerificationFailed passkeyVerificationFailed,
            Clock clock) {
        var eventName = "AUTH_PASSKEY_VERIFICATION_FAILED";
        Instant now = clock.instant();
        var user = UserWithoutPhone.fromAuditContext(auditContext);
        var extensions = new Extensions(journeyType.getValue(), passkeyVerificationFailed);
        var restricted =
                new Restricted(
                        EncodedDeviceInformation.from(auditContext),
                        new RestrictedPasskeySection(passkeyAllowCredentials, passkeyCredentialId));
        return new AuthPasskeyVerificationFailed(
                eventName,
                now.getEpochSecond(),
                now.toEpochMilli(),
                auditContext.clientId(),
                ComponentId.AUTH.getValue(),
                user,
                restricted,
                extensions);
    }

    public record PasskeyVerificationFailed(
            PasskeyAuthenticationRequest passkeyAuthenticationRequest,
            int passkeyCounter,
            boolean passkeyCredentialBackedUp,
            String passkeyCredentialDeviceType,
            boolean passkeyUserVerified,
            String passkeyVerificationFailureReason) {}

    public record Extensions(
            @SerializedName("journey-type") String journeyType,
            PasskeyVerificationFailed passkey) {}

    public record RestrictedPasskeySection(
            List<PasskeyAllowCredentials> passkeyAllowedCredentials, String passkeyCredentialId) {}

    public record Restricted(
            EncodedDeviceInformation deviceInformation, RestrictedPasskeySection passkey) {}
}
