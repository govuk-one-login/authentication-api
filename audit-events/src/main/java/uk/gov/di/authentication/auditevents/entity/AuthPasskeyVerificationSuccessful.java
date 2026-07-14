package uk.gov.di.authentication.auditevents.entity;

import com.google.gson.annotations.SerializedName;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.auditevents.entity.shared.EncodedDeviceInformation;
import uk.gov.di.authentication.auditevents.entity.shared.Users.UserWithoutPhone;
import uk.gov.di.authentication.auditevents.entity.shared.passkeys.PasskeyAllowCredentials;
import uk.gov.di.authentication.auditevents.entity.shared.passkeys.PasskeyDetail;
import uk.gov.di.authentication.auditevents.entity.shared.passkeys.RestrictedPasskeySection;
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
            String publicSubjectId,
            Clock clock) {
        var eventName = "AUTH_PASSKEY_VERIFICATION_SUCCESSFUL";
        Instant now = clock.instant();
        var user = UserWithoutPhone.fromAuditContext(auditContext, publicSubjectId);
        var restricted =
                new Restricted(
                        EncodedDeviceInformation.from(auditContext),
                        new RestrictedPasskeySection(passkeyAllowedCredentials, credentialId));
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

    public record Restricted(
            EncodedDeviceInformation deviceInformation, RestrictedPasskeySection passkey) {}

    public record Extensions(
            @SerializedName("journey-type") String journeyType, PasskeyDetail passkey) {}
}
