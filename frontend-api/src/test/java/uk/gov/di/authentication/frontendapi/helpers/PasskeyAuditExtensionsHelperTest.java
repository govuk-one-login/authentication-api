package uk.gov.di.authentication.frontendapi.helpers;

import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import com.yubico.webauthn.data.UserVerificationRequirement;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.auditevents.entity.shared.passkeys.PasskeyAllowCredentials;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class PasskeyAuditExtensionsHelperTest {

    private static AssertionRequest buildAssertionRequest(
            List<PublicKeyCredentialDescriptor> allowCredentials) {
        var options =
                PublicKeyCredentialRequestOptions.builder()
                        .challenge(new ByteArray("test-challenge".getBytes(StandardCharsets.UTF_8)))
                        .allowCredentials(allowCredentials)
                        .build();
        return AssertionRequest.builder().publicKeyCredentialRequestOptions(options).build();
    }

    private static AssertionRequest buildAssertionRequest(
            Optional<UserVerificationRequirement> mayebUserVerificationRequirement) {

        var optionsBuilder =
                PublicKeyCredentialRequestOptions.builder()
                        .challenge(
                                new ByteArray("test-challenge".getBytes(StandardCharsets.UTF_8)));
        mayebUserVerificationRequirement.ifPresent(optionsBuilder::userVerification);
        var options = optionsBuilder.build();
        return AssertionRequest.builder().publicKeyCredentialRequestOptions(options).build();
    }

    @Nested
    class PasskeyAllowedCredentialsFrom {

        @Test
        void shouldReturnEmptyListWhenNoAllowCredentials() {
            var assertionRequest = buildAssertionRequest(List.of());

            var result =
                    PasskeyAuditExtensionsHelper.passkeyAllowedCredentialsFrom(assertionRequest);

            assertEquals(List.of(), result);
        }

        @Test
        void shouldMapCredentialIdToBase64UrlAndTransports() {
            var credentialId = new ByteArray("cred-1".getBytes(StandardCharsets.UTF_8));
            var descriptor =
                    PublicKeyCredentialDescriptor.builder()
                            .id(credentialId)
                            .transports(Set.of(AuthenticatorTransport.USB))
                            .build();

            var result =
                    PasskeyAuditExtensionsHelper.passkeyAllowedCredentialsFrom(
                            buildAssertionRequest(List.of(descriptor)));

            assertEquals(1, result.size());
            assertEquals(
                    new PasskeyAllowCredentials(credentialId.getBase64Url(), List.of("usb")),
                    result.get(0));
        }

        @Test
        void shouldMapMultipleTransports() {
            var credentialId = new ByteArray("cred-2".getBytes(StandardCharsets.UTF_8));
            var descriptor =
                    PublicKeyCredentialDescriptor.builder()
                            .id(credentialId)
                            .transports(
                                    Set.of(
                                            AuthenticatorTransport.BLE,
                                            AuthenticatorTransport.INTERNAL))
                            .build();

            var result =
                    PasskeyAuditExtensionsHelper.passkeyAllowedCredentialsFrom(
                            buildAssertionRequest(List.of(descriptor)));

            assertEquals(1, result.size());
            assertEquals(credentialId.getBase64Url(), result.get(0).passkeyCredentialId());
            // Sets are unordered, so check contents rather than order
            assertEquals(
                    Set.of("ble", "internal"),
                    Set.copyOf(result.get(0).passkeyCredentialTransports()));
        }

        @Test
        void shouldSetTransportsToNullWhenAbsent() {
            var credentialId = new ByteArray("cred-3".getBytes(StandardCharsets.UTF_8));
            // builder without .transports() leaves transports absent
            var descriptor = PublicKeyCredentialDescriptor.builder().id(credentialId).build();

            var result =
                    PasskeyAuditExtensionsHelper.passkeyAllowedCredentialsFrom(
                            buildAssertionRequest(List.of(descriptor)));

            assertEquals(1, result.size());
            assertNull(result.get(0).passkeyCredentialTransports());
        }

        @Test
        void shouldMapMultipleCredentials() {
            var id1 = new ByteArray("cred-a".getBytes(StandardCharsets.UTF_8));
            var id2 = new ByteArray("cred-b".getBytes(StandardCharsets.UTF_8));
            var descriptors =
                    List.of(
                            PublicKeyCredentialDescriptor.builder()
                                    .id(id1)
                                    .transports(Set.of(AuthenticatorTransport.USB))
                                    .build(),
                            PublicKeyCredentialDescriptor.builder()
                                    .id(id2)
                                    .transports(Set.of(AuthenticatorTransport.NFC))
                                    .build());

            var result =
                    PasskeyAuditExtensionsHelper.passkeyAllowedCredentialsFrom(
                            buildAssertionRequest(descriptors));

            assertEquals(2, result.size());
            assertEquals(
                    new PasskeyAllowCredentials(id1.getBase64Url(), List.of("usb")), result.get(0));
            assertEquals(
                    new PasskeyAllowCredentials(id2.getBase64Url(), List.of("nfc")), result.get(1));
        }
    }

    @Nested
    class UserVerificationStringFrom {
        @Test
        void getsUserVerificationStringIfItExists() {
            var assertionRequest =
                    buildAssertionRequest(Optional.of(UserVerificationRequirement.REQUIRED));

            var result = PasskeyAuditExtensionsHelper.userVerificationStringFrom(assertionRequest);

            assertEquals("required", result);
        }

        @Test
        void getsEmptyStringIfUserRequirementNotOnAssertionRequest() {
            var assertionRequest = buildAssertionRequest(Optional.empty());

            var result = PasskeyAuditExtensionsHelper.userVerificationStringFrom(assertionRequest);

            assertEquals("", result);
        }
    }
}
