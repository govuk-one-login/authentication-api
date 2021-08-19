package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.domain.AuditableEvent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.shared.services.AuditServiceTest.TestEvents.TEST_EVENT_ONE;

class AuditServiceTest {

    enum TestEvents implements AuditableEvent {
        TEST_EVENT_ONE
    }

    @Test
    void shouldLogAuditEvent() {
        var auditService = new AuditService();

        assertEquals(
                auditService.generateLogLine(TEST_EVENT_ONE),
                "Emitting audit event - TEST_EVENT_ONE");
    }
}
