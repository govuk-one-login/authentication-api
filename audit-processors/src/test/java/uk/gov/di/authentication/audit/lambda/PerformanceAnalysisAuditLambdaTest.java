package uk.gov.di.authentication.audit.lambda;

import org.apache.logging.log4j.core.LogEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.audit.AuditPayload;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.nio.ByteBuffer;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.hasObjectMessageProperty;

class PerformanceAnalysisAuditLambdaTest {

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(PerformanceAnalysisAuditLambda.class);

    private final KmsConnectionService kms = mock(KmsConnectionService.class);
    private final ConfigurationService config = mock(ConfigurationService.class);

    @BeforeEach
    public void setUp() {
        when(kms.validateSignature(any(ByteBuffer.class), any(ByteBuffer.class), eq("key_alias")))
                .thenReturn(true);
    }

    @Test
    void handlesRequestsAppropriately() {
        var handler = new PerformanceAnalysisAuditLambda(kms, config);

        var payload =
                AuditPayload.AuditEvent.newBuilder()
                        .setEventId("test-event-id")
                        .setRequestId("test-request-id")
                        .setClientId("test-client-id")
                        .setTimestamp("test-timestamp")
                        .setEventName("test-event-name")
                        .setPersistentSessionId("test-persistent-session-id")
                        .build();

        handler.handleAuditEvent(payload);

        LogEvent logEvent = logging.events().get(0);

        assertThat(logEvent, hasObjectMessageProperty("event-id", "test-event-id"));
        assertThat(logEvent, hasObjectMessageProperty("request-id", "test-request-id"));
        assertThat(logEvent, hasObjectMessageProperty("timestamp", "test-timestamp"));
        assertThat(logEvent, hasObjectMessageProperty("event-name", "test-event-name"));
    }
}
