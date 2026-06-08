package uk.gov.di.authentication.frontendapi.entity.passkeys.audit;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class PasskeyAllowedCredentialSerializerTest {

    private final SerializationService serializer = SerializationService.getInstance();

    @Test
    void shouldIncludeTransportsWhenPresent() {
        var credential =
                new PasskeyAuthenticationAuditRestricted.PasskeyAllowedCredential(
                        "cred-id", List.of("usb", "nfc"));

        String json = serializer.writeValueAsString(credential);

        assertEquals(
                """
                {"passkey_credential_id":"cred-id","passkey_credential_transports":["usb","nfc"]}""",
                json);
    }

    @Test
    void shouldOmitTransportsWhenNull() {
        var credential =
                new PasskeyAuthenticationAuditRestricted.PasskeyAllowedCredential("cred-id", null);

        String json = serializer.writeValueAsString(credential);

        assertEquals("""
                {"passkey_credential_id":"cred-id"}""", json);
    }

    @Test
    void shouldOmitTransportsWhenEmpty() {
        var credential =
                new PasskeyAuthenticationAuditRestricted.PasskeyAllowedCredential(
                        "cred-id", List.of());

        String json = serializer.writeValueAsString(credential);

        assertEquals("""
                {"passkey_credential_id":"cred-id"}""", json);
    }
}
