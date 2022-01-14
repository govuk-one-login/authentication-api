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
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.doesNotHaveObjectMessageProperty;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.hasObjectMessageProperty;

class PerformanceAnalysisAuditLambdaTest {

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(PerformanceAnalysisAuditLambda.class);

    private final KmsConnectionService kms = mock(KmsConnectionService.class);
    private final ConfigurationService config = mock(ConfigurationService.class);

    @BeforeEach
    public void setUp() {
        when(config.getAuditSigningKeyAlias()).thenReturn("key_alias");
        when(config.getAuditHmacSecret()).thenReturn("i-am-a-fake-hash-key");
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
                        .setSessionId("test-session-id")
                        .setClientId("test-client-id")
                        .setTimestamp("test-timestamp")
                        .setEventName("test-event-name")
                        .setPersistentSessionId("test-persistent-session-id")
                        .build();

        handler.handleAuditEvent(payload);

        LogEvent logEvent = logging.events().get(0);

        assertThat(logEvent, hasObjectMessageProperty("event-id", "test-event-id"));
        assertThat(logEvent, hasObjectMessageProperty("request-id", "test-request-id"));
        assertThat(logEvent, hasObjectMessageProperty("session-id", "test-session-id"));
        assertThat(logEvent, hasObjectMessageProperty("timestamp", "test-timestamp"));
        assertThat(logEvent, hasObjectMessageProperty("event-name", "test-event-name"));
    }

    @Test
    void shouldHashSensitiveFields() {
        var handler = new PerformanceAnalysisAuditLambda(kms, config);

        var payload =
                AuditPayload.AuditEvent.newBuilder()
                        .setUser(
                                AuditPayload.AuditEvent.User.newBuilder()
                                        .setId("test-id")
                                        .setEmail("test-example@digital.cabinet-office.gov.uk")
                                        .setPhoneNumber("test-phone-number")
                                        .setIpAddress("test-ip-address")
                                        .build())
                        .build();

        handler.handleAuditEvent(payload);

        LogEvent logEvent = logging.events().get(0);

        assertThat(
                logEvent,
                hasObjectMessageProperty(
                        "user-id",
                        "fe3ad3ffe725ab111628ea3df4b04fb0fda486479fb621c8d4ac325c9e1ce91b"));
    }

    @Test
    void shouldNotHashMissingSensitiveFields_Id() {
        var handler = new PerformanceAnalysisAuditLambda(kms, config);

        var payload =
                AuditPayload.AuditEvent.newBuilder()
                        .setUser(
                                AuditPayload.AuditEvent.User.newBuilder()
                                        .setEmail("test-email")
                                        .setPhoneNumber("test-phone")
                                        .build())
                        .build();

        handler.handleAuditEvent(payload);

        LogEvent logEvent = logging.events().get(0);

        assertThat(logEvent, doesNotHaveObjectMessageProperty("user.id"));
    }
}
