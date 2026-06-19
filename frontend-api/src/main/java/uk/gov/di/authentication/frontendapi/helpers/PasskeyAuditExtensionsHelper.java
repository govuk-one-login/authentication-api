package uk.gov.di.authentication.frontendapi.helpers;

import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.UserVerificationRequirement;
import uk.gov.di.authentication.auditevents.entity.shared.passkeys.PasskeyAllowCredentials;
import uk.gov.di.authentication.shared.services.AuditService;

import java.util.List;

public class PasskeyAuditExtensionsHelper {
    private PasskeyAuditExtensionsHelper() {
        /* This utility class should not be instantiated */
    }

    public static List<PasskeyAllowCredentials> passkeyAllowedCredentialsFrom(
            AssertionRequest assertionRequest) {
        var allowCredentials =
                assertionRequest
                        .getPublicKeyCredentialRequestOptions()
                        .getAllowCredentials()
                        .orElse(List.of());
        return allowCredentials.stream()
                .map(
                        c ->
                                new PasskeyAllowCredentials(
                                        c.getId().getBase64Url(), getNullableTransports(c)))
                .toList();
    }

    public static String userVerificationStringFrom(AssertionRequest assertionRequest) {
        return assertionRequest
                .getPublicKeyCredentialRequestOptions()
                .getUserVerification()
                .map(UserVerificationRequirement::getValue)
                .orElse(AuditService.UNKNOWN);
    }

    private static List<String> getNullableTransports(PublicKeyCredentialDescriptor credential) {
        var transportsAsList =
                credential
                        .getTransports()
                        .map(set -> set.stream().map(AuthenticatorTransport::getId).toList())
                        .orElse(List.of());
        return transportsAsList.isEmpty() ? null : transportsAsList;
    }
}
