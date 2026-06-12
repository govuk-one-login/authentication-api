package uk.gov.di.authentication.auditevents.entity;

import org.junit.jupiter.api.Test;
import uk.gov.di.audit.AuditContext;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.asJson;

class AuthPasskeyDeleteSuccessfulTest {

    @Test
    void shouldSerialiseAnAuthPasskeyDeleteSuccessfulAuditEvent() {
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

        var event =
                AuthPasskeyDeleteSuccessful.create(auditContext, 2, "credential-id", fixedClock);

        var actualEvent = event.serialize();

        var expectedEvent =
                """
                {
                  "event_name": "AUTH_PASSKEY_DELETE_SUCCESSFUL",
                  "timestamp": 1781097184,
                  "event_timestamp_ms": 1781097184730,
                  "client_id": "client-id",
                  "component_id": "HOME",
                  "user": {
                    "email": "test@example.com",
                    "govuk_signin_journey_id": "signin-journey-id",
                    "ip_address": "192.0.2.0/24",
                    "persistent_session_id": "persistent-session-id",
                    "session_id": "session-id",
                    "user_id": "internal-common-subject-id",
                    "passkey_count": 2
                  },
                  "restricted": {
                    "device_information": {
                      "encoded": "encoded-device-info"
                    },
                    "passkey": {
                      "passkey_credential_id": "credential-id"
                    }
                  },
                  "extensions": {
                    "journey-type": "ACCOUNT_MANAGEMENT"
                  }
                }
                """;

        assertEquals(asJson(expectedEvent), asJson(actualEvent));
    }
}
