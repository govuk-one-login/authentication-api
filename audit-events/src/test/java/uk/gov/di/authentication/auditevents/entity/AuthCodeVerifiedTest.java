package uk.gov.di.authentication.auditevents.entity;

import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;
import uk.gov.di.audit.AuditContext;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.asJson;

class AuthCodeVerifiedTest {

    private static final Instant FIXED_INSTANT = Instant.parse("2026-06-10T13:13:04.730565Z");
    private static final Clock FIXED_CLOCK = Clock.fixed(FIXED_INSTANT, ZoneOffset.UTC);

    private final AuditContext auditContext =
            AuditContext.emptyAuditContext()
                    .withClientId("client-id")
                    .withEmail("test@example.com")
                    .withSubjectId("internal-common-subject-id")
                    .withPersistentSessionId("persistent-session-id")
                    .withSessionId("session-id")
                    .withClientSessionId("signin-journey-id")
                    .withIpAddress("192.0.2.0/24")
                    .withTxmaAuditEncoded("encoded-device-info");

    @Test
    void shouldSerialiseAnAuthCodeVerifiedAuditEventWithAllExtensions() {
        var extensions =
                new AuthCodeVerified.Extensions(
                        "MFA_SMS", 0, false, "SIGN_IN", "196306", "SMS", "default");

        var event =
                AuthCodeVerified.create(
                        auditContext,
                        "urn:fdc:gov.uk:2022:public-subject-id",
                        ComponentId.AUTH,
                        extensions,
                        FIXED_CLOCK);

        var actualEvent = event.serialize();

        var expectedEvent =
                """
                {
                  "event_name": "AUTH_CODE_VERIFIED",
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
                    }
                  },
                  "extensions": {
                    "notification-type": "MFA_SMS",
                    "loginFailureCount": 0,
                    "account-recovery": false,
                    "journey-type": "SIGN_IN",
                    "MFACodeEntered": "196306",
                    "mfa-type": "SMS",
                    "mfa-method": "default"
                  }
                }
                """;

        assertEquals(asJson(expectedEvent), asJson(actualEvent));
    }

    @Test
    void shouldSerialiseAnAuthCodeVerifiedAuditEventWithMinimalExtensions() {
        var extensions =
                new AuthCodeVerified.Extensions(
                        null, null, false, "ACCOUNT_MANAGEMENT", null, "AUTH_APP", "backup");

        var event =
                AuthCodeVerified.create(
                        auditContext,
                        "urn:fdc:gov.uk:2022:public-subject-id",
                        ComponentId.HOME,
                        extensions,
                        FIXED_CLOCK);

        var actualEvent = event.serialize();
        var actualEventAsJsonObject = JsonParser.parseString(actualEvent).getAsJsonObject();

        var expectedExtensions =
                """
                {
                  "account-recovery": false,
                  "journey-type": "ACCOUNT_MANAGEMENT",
                  "mfa-type": "AUTH_APP",
                  "mfa-method": "backup"
                }
                """;

        var actualExtensionsSection = actualEventAsJsonObject.get("extensions");
        assertEquals(asJson(expectedExtensions), actualExtensionsSection);
    }
}
