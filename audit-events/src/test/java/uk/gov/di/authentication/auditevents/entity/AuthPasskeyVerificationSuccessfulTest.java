package uk.gov.di.authentication.auditevents.entity;

import org.junit.jupiter.api.Test;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.auditevents.entity.shared.passkeys.PasskeyAllowCredentials;
import uk.gov.di.authentication.auditevents.entity.shared.passkeys.PasskeyDetail;
import uk.gov.di.authentication.shared.entity.JourneyType;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.asJson;

class AuthPasskeyVerificationSuccessfulTest {

    @Test
    void shouldSerialiseAnAuthPasskeyVerificationSuccessfulAuditEvent() {
        var auditContext =
                AuditContext.emptyAuditContext()
                        .withClientId("client-id")
                        .withEmail("test@example.com")
                        .withSubjectId("internal-common-subject-id")
                        .withPersistentSessionId("persistent-session-id")
                        .withSessionId("session-id")
                        .withClientSessionId("signin-journey-id")
                        .withIpAddress("192.0.2.0/24")
                        .withTxmaAuditEncoded("encoded-device-info");

        var fixedInstant = Instant.parse("2026-06-10T13:13:04.730565Z");
        var fixedClock = Clock.fixed(fixedInstant, ZoneOffset.UTC);

        var passkeyAllowCredentials =
                List.of(
                        new PasskeyAllowCredentials("credential-1", null),
                        new PasskeyAllowCredentials("credential-2", List.of("ble")));
        var passkey = PasskeyDetail.verificationSuccessful("required", 0, true, "multi-device");
        var event =
                AuthPasskeyVerificationSuccessful.create(
                        auditContext,
                        JourneyType.SIGN_IN,
                        passkeyAllowCredentials,
                        passkey,
                        "credential-1",
                        "urn:fdc:gov.uk:2022:public-subject-id",
                        fixedClock);

        var actualEvent = event.serialize();

        var expectedEvent =
                """
                {
                  "event_name": "AUTH_PASSKEY_VERIFICATION_SUCCESSFUL",
                  "timestamp": 1781097184,
                  "event_timestamp_ms": 1781097184730,
                  "client_id": "client-id",
                  "component_id": "AUTH",
                  "user": {
                    "email": "test@example.com",
                    "govuk_signin_journey_id": "signin-journey-id",
                    "ip_address": "192.0.2.0/24",
                    "persistent_session_id": "persistent-session-id",
                    "session_id": "session-id",
                    "user_id": "internal-common-subject-id",
                    "public_subject_id": "urn:fdc:gov.uk:2022:public-subject-id"
                  },
                  "restricted": {
                    "device_information": {
                      "encoded": "encoded-device-info"
                    },
                    "passkey": {
                      "passkey_allowed_credentials": [
                        {
                          "passkey_credential_id": "credential-1"
                        },
                        {
                          "passkey_credential_id": "credential-2",
                          "passkey_credential_transports": [
                            "ble"
                          ]
                        }
                      ],
                      "passkey_credential_id": "credential-1"
                    }
                  },
                  "extensions": {
                    "journey-type": "SIGN_IN",
                    "passkey": {
                      "passkey_authentication_request": {
                        "passkey_request_user_verification": "required"
                      },
                      "passkey_counter": 0,
                      "passkey_credential_backed_up": true,
                      "passkey_credential_device_type": "multi-device",
                      "passkey_user_verified": true
                    }
                  }
                }
                """;

        assertEquals(asJson(expectedEvent), asJson(actualEvent));
    }
}
