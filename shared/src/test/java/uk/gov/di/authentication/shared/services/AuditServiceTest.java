package uk.gov.di.authentication.shared.services;

import com.google.protobuf.ByteString;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.MockitoAnnotations;
import uk.gov.di.audit.AuditPayload;
import uk.gov.di.authentication.shared.domain.AuditableEvent;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.AuditServiceTest.TestEvents.TEST_EVENT_ONE;

class AuditServiceTest {

    private static final String FIXED_TIMESTAMP = "2021-09-01T22:10:00.012Z";
    private static final Clock FIXED_CLOCK =
            Clock.fixed(Instant.parse(FIXED_TIMESTAMP), ZoneId.of("UTC"));

    private final SnsService snsService = mock(SnsService.class);

    @Captor private ArgumentCaptor<String> messageCaptor;

    enum TestEvents implements AuditableEvent {
        TEST_EVENT_ONE
    }

    @BeforeEach
    public void beforeEach() {
        MockitoAnnotations.openMocks(this);
    }

    @AfterEach
    public void afterEach() {
        verifyNoMoreInteractions(snsService);
    }

    @Test
    void shouldLogAuditEvent() throws Exception {
        var auditService = new AuditService(FIXED_CLOCK, snsService);

        auditService.submitAuditEvent(TEST_EVENT_ONE);

        verify(snsService).publishAuditMessage(messageCaptor.capture());

        var signedAuditEvent =
                AuditPayload.SignedAuditEvent.parseFrom(
                        ByteString.copyFromUtf8(messageCaptor.getValue()));
        var auditEvent = AuditPayload.AuditEvent.parseFrom(signedAuditEvent.getPayload());

        MatcherAssert.assertThat(auditEvent.getTimestamp(), equalTo(FIXED_TIMESTAMP));

        MatcherAssert.assertThat(
                auditEvent.getEventNameBytes().toStringUtf8(), equalTo(TEST_EVENT_ONE.toString()));
    }

    @Test
    void shouldLogAuditEventWithMetadataPairsAttached() throws Exception {
        var auditService = new AuditService(FIXED_CLOCK, snsService);

        auditService.submitAuditEvent(TEST_EVENT_ONE, pair("key", "value"), pair("key2", "value2"));

        verify(snsService).publishAuditMessage(messageCaptor.capture());

        var signedAuditEvent =
                AuditPayload.SignedAuditEvent.parseFrom(
                        ByteString.copyFromUtf8(messageCaptor.getValue()));
        var auditEvent = AuditPayload.AuditEvent.parseFrom(signedAuditEvent.getPayload());

        MatcherAssert.assertThat(auditEvent.getTimestamp(), equalTo(FIXED_TIMESTAMP));

        MatcherAssert.assertThat(
                auditEvent.getEventNameBytes().toStringUtf8(), equalTo(TEST_EVENT_ONE.toString()));
    }
}
