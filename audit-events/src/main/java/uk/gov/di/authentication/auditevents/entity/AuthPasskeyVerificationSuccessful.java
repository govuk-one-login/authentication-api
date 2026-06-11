package uk.gov.di.authentication.auditevents.entity;

import com.google.gson.annotations.SerializedName;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.auditevents.entity.shared.EncodedDeviceInformation;
import uk.gov.di.authentication.auditevents.entity.shared.Users.UserWithoutPhone;
import uk.gov.di.authentication.auditevents.entity.shared.passkeys.PasskeyAllowCredentials;
import uk.gov.di.authentication.auditevents.entity.shared.passkeys.PasskeyAuthenticationRequest;
import uk.gov.di.authentication.auditevents.entity.shared.passkeys.PasskeyDetail;
import uk.gov.di.authentication.shared.entity.JourneyType;

import java.time.Clock;
import java.time.Instant;
import java.util.List;

public record AuthPasskeyVerificationSuccessful(
        String eventName,
        long timestamp,
        long eventTimestampMs,
        String clientId,
        String componentId,
        UserWithoutPhone user,
        Restricted restricted,
        Extensions extensions)
        implements StructuredAuditEvent {

    public static AuthPasskeyVerificationSuccessful create(
            AuditContext auditContext,
            JourneyType journeyType,
            List<PasskeyAllowCredentials> passkeyAllowedCredentials,
            PasskeyDetail passkey,
            String credentialId,
            Clock clock) {
        var eventName = "AUTH_PASSKEY_VERIFICATION_SUCCESSFUL";
        Instant now = clock.instant();
        var user = UserWithoutPhone.fromAuditContext(auditContext);
        var restricted =
                new Restricted(
                        EncodedDeviceInformation.from(auditContext),
                        new RestrictedPasskeySection(passkeyAllowedCredentials),
                        credentialId);
        var extensions = new Extensions(journeyType.getValue(), passkey);
        return new AuthPasskeyVerificationSuccessful(
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
            boolean passkeyUserVerified,
            PasskeyAuthenticationRequest passkeyAuthenticationRequest) {}

    public record RestrictedPasskeySection(
            List<PasskeyAllowCredentials> passkeyAllowedCredentials) {}

    public record Restricted(
            EncodedDeviceInformation deviceInformation,
            RestrictedPasskeySection passkey,
            String passkeyCredentialId) {}

    public record Extensions(
            @SerializedName("journey-type") String journeyType, PasskeyDetail passkey) {}
}
