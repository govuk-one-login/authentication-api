package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.domain.AuditableEvent;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.AuditServiceTest.TestEvents.TEST_EVENT_ONE;

class AuditServiceTest {

    private final SnsService snsService = mock(SnsService.class);

    enum TestEvents implements AuditableEvent {
        TEST_EVENT_ONE
    }

    @AfterEach
    public void afterEach() {
        verifyNoMoreInteractions(snsService);
    }

    @Test
    void shouldLogAuditEvent() {
        var auditService = new AuditService(snsService);

        auditService.submitAuditEvent(TEST_EVENT_ONE);

        verify(snsService).publishAuditMessage(eq("Emitting audit event - TEST_EVENT_ONE"));
    }

    @Test
    void shouldLogAuditEventWithMetadataPairsAttached() {
        var auditService = new AuditService(snsService);

        auditService.submitAuditEvent(TEST_EVENT_ONE, pair("key", "value"), pair("key2", "value2"));

        verify(snsService)
                .publishAuditMessage(
                        eq(
                                "Emitting audit event - TEST_EVENT_ONE => [key: value], [key2: value2]"));
    }
}
