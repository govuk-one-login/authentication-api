package uk.gov.di.authentication.auditevents.entity;

import org.junit.jupiter.api.Test;
import uk.gov.di.audit.AuditContext;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.sharedtest.matchers.JsonMatcher.asJson;

class AuthTokenSentToOrchestrationTest {

    @Test
    void shouldSerialiseAnAuthTokenSentToOrchestrationAuditEvent() {
        var auditContext =
                AuditContext.emptyAuditContext()
                        .withClientId("client-id")
                        .withSubjectId("urn:fdc:gov.uk:2022:internal-pairwise-id")
                        .withClientSessionId("signin-journey-id");

        var fixedInstant = Instant.parse("2026-06-10T13:13:04.730565Z");
        var fixedClock = Clock.fixed(fixedInstant, ZoneOffset.UTC);

        var event =
                AuthTokenSentToOrchestration.create(
                        auditContext,
                        "test@example.com",
                        "urn:fdc:gov.uk:2022:public-subject-id",
                        fixedClock);

        var actualEvent = event.serialize();

        var expectedEvent =
                """
                {
                  "event_name": "AUTH_TOKEN_SENT_TO_ORCHESTRATION",
                  "timestamp": 1781097184,
                  "event_timestamp_ms": 1781097184730,
                  "client_id": "client-id",
                  "component_id": "AUTH",
                  "user": {
                    "user_id": "urn:fdc:gov.uk:2022:internal-pairwise-id",
                    "email": "test@example.com",
                    "public_subject_id": "urn:fdc:gov.uk:2022:public-subject-id"
                  }
                }
                """;

        assertEquals(asJson(expectedEvent), asJson(actualEvent));
    }
}
