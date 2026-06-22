package uk.gov.di.authentication.auditevents.entity;

import com.google.gson.JsonParser;
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

class AuthPasskeyVerificationFailedTest {
    private static final AuditContext AUDIT_CONTEXT =
            AuditContext.emptyAuditContext()
                    .withClientId("client-id")
                    .withEmail("test@example.com")
                    .withSubjectId("internal-common-subject-id")
                    .withPersistentSessionId("persistent-session-id")
                    .withSessionId("session-id")
                    .withClientSessionId("signin-journey-id")
                    .withIpAddress("192.0.2.0/24")
                    .withTxmaAuditEncoded("encoded-device-info");

    private static final Instant FIXED_INSTANT = Instant.parse("2026-06-10T13:13:04.730565Z");
    private static final Clock FIXED_CLOCK = Clock.fixed(FIXED_INSTANT, ZoneOffset.UTC);

    @Test
    void shouldSerialiseAnAuthPasskeyVerificationFailedAuditEvent() {
        var passkeyAllowCredentials =
                List.of(
                        new PasskeyAllowCredentials("credential-1", null),
                        new PasskeyAllowCredentials("credential-2", List.of("ble")));

        var passkeyVerificationFailed =
                PasskeyDetail.verificationFailed(
                        "required", 0, true, "multi-device", "Verification failed");

        var event =
                AuthPasskeyVerificationFailed.create(
                        AUDIT_CONTEXT,
                        JourneyType.SIGN_IN,
                        passkeyAllowCredentials,
                        "credential-1",
                        passkeyVerificationFailed,
                        FIXED_CLOCK);

        var actualEvent = event.serialize();

        var expectedEvent =
                """
                        {
                          "event_name": "AUTH_PASSKEY_VERIFICATION_FAILED",
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
                            "user_id": "internal-common-subject-id"
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
                              "passkey_user_verified": false,
                              "passkey_verification_failure_reason": "Verification failed"
                            }
                          }
                        }
                        """;

        assertEquals(asJson(expectedEvent), asJson(actualEvent));
    }

    @Test
    void shouldSerialiseAnAuthPasskeyVerificationFailedAuditEventWhenVerificationCouldNotProceed() {
        var passkeyVerificationFailed =
                PasskeyDetail.verificationCouldNotProceed(
                        "Stored assertion request failed to parse");

        var event =
                AuthPasskeyVerificationFailed.create(
                        AUDIT_CONTEXT,
                        JourneyType.SIGN_IN,
                        null,
                        null,
                        passkeyVerificationFailed,
                        FIXED_CLOCK);

        var actualEvent = event.serialize();
        var actualEventAsJsonObject = JsonParser.parseString(actualEvent).getAsJsonObject();

        var expectedRestrictedSection =
                """
                        {
                          "device_information": {
                            "encoded": "encoded-device-info"
                          },
                          "passkey": {}
                        }
                        """;
        var actualRestrictedSection = actualEventAsJsonObject.get("restricted");

        assertEquals(asJson(expectedRestrictedSection), actualRestrictedSection);

        var expectedExtensions =
                """
                        {
                            "journey-type": "SIGN_IN",
                            "passkey": {
                              "passkey_user_verified": false,
                              "passkey_verification_failure_reason": "Stored assertion request failed to parse"
                            }
                          }
                        """;

        var actualExtensionsSection = actualEventAsJsonObject.get("extensions");
        assertEquals(asJson(expectedExtensions), actualExtensionsSection);
    }
}
