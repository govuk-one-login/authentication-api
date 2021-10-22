package uk.gov.di.authentication.audit.lambda;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.impl.MutableLogEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.audit.AuditPayload.AuditEvent;
import uk.gov.di.audit.AuditPayload.AuditEvent.User;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.matchers.LogEventMatcher.hasMDCProperty;

public class CounterFraudAuditLambdaTest {

    private final KmsConnectionService kms = mock(KmsConnectionService.class);
    private final ConfigurationService config = mock(ConfigurationService.class);
    private final ListAppender appender = new ListAppender();

    @BeforeEach
    public void setUp() {
        Logger logger = (Logger) LogManager.getLogger(CounterFraudAuditLambda.class);

        appender.start();
        logger.addAppender(appender);

        when(config.getAuditSigningKeyAlias()).thenReturn("key_alias");
        when(config.getAuditHmacSecret()).thenReturn("i-am-a-fake-hash-key");
        when(kms.validateSignature(any(ByteBuffer.class), any(ByteBuffer.class), anyString()))
                .thenReturn(true);
    }

    @Test
    void handlesRequestsAppropriately() {
        var handler = new CounterFraudAuditLambda(kms, config);

        var payload = AuditEvent.newBuilder().setEventId("foo").build();

        handler.handleAuditEvent(payload);

        LogEvent logEvent = appender.getEvents().get(1);

        assertThat(logEvent, hasMDCProperty("event-id", "foo"));
    }

    @Test
    void shouldHashSensitiveFields() {
        var handler = new CounterFraudAuditLambda(kms, config);

        var payload =
                AuditEvent.newBuilder()
                        .setEventId("foo")
                        .setUser(
                                User.newBuilder()
                                        .setEmail("test-example@digital.cabinet-office.gov.uk")
                                        .setId("some-id")
                                        .setPhoneNumber("some-phone-number")
                                        .build())
                        .build();

        handler.handleAuditEvent(payload);

        LogEvent logEvent = appender.getEvents().get(1);

        assertThat(
                logEvent,
                hasMDCProperty(
                        "user.email",
                        "dbc2c80d5e663075eb736f52df8446c109878f1a27b9d2f7db634d4e64923c94"));
        assertThat(
                logEvent,
                hasMDCProperty(
                        "user.id",
                        "0e49411b4a5da564d867bef289f129fe7faa1d3341a458344e790c522d451a20"));
        assertThat(
                logEvent,
                hasMDCProperty(
                        "user.phone",
                        "f264cf9189f466ecdec47c450dfd0e13a59f85dfc1e63ef93d3870ef6b927821"));
    }

    public static class ListAppender extends AbstractAppender {

        final List<LogEvent> events = Collections.synchronizedList(new ArrayList<>());

        public ListAppender() {
            super("StubAppender", null, null, true, Property.EMPTY_ARRAY);
        }

        @Override
        public void append(final LogEvent event) {
            if (event instanceof MutableLogEvent) {
                events.add(((MutableLogEvent) event).createMemento());
            } else {
                events.add(event);
            }
        }

        public List<LogEvent> getEvents() {
            return events;
        }
    }

    @AfterEach
    public void tearDown() {
        Logger logger = (Logger) LogManager.getLogger(CounterFraudAuditLambda.class);
        logger.removeAppender(appender);
    }
}
