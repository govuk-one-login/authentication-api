package uk.gov.di.authentication.audit.lambda;

import com.amazonaws.services.lambda.runtime.events.SNSEvent;
import com.google.protobuf.AbstractMessageLite;
import com.google.protobuf.ByteString;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.impl.MutableLogEvent;
import org.junit.jupiter.api.Test;
import uk.gov.di.audit.AuditPayload.AuditEvent;
import uk.gov.di.audit.AuditPayload.SignedAuditEvent;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.matchers.LogEventMatcher.hasMDCProperty;

public class CounterFraudAuditLambdaTest {

    private final KmsConnectionService kms = mock(KmsConnectionService.class);
    private final ConfigurationService config = mock(ConfigurationService.class);

    @Test
    void handlesRequestsAppropriately() {
        Logger logger = (Logger) LogManager.getLogger(CounterFraudAuditLambda.class);

        var appender = new ListAppender();
        appender.start();

        logger.addAppender(appender);

        when(config.getAuditSigningKeyAlias()).thenReturn("key_alias");
        when(kms.validateSignature(any(ByteBuffer.class), any(ByteBuffer.class), anyString()))
                .thenReturn(true);

        var handler = new CounterFraudAuditLambda(kms, config);

        var payload =
                SignedAuditEvent.newBuilder()
                        .setSignature(ByteString.copyFrom("signature".getBytes()))
                        .setPayload(
                                AuditEvent.newBuilder().setEventId("foo").build().toByteString())
                        .build();

        handler.handleRequest(inputEvent(payload), null);

        LogEvent logEvent = appender.getEvents().get(1);

        assertThat(logEvent, hasMDCProperty("event-id", "foo"));
    }

    private SNSEvent inputEvent(SignedAuditEvent payload) {
        return Optional.of(payload)
                .map(AbstractMessageLite::toByteArray)
                .map(Base64.getEncoder()::encodeToString)
                .map(new SNSEvent.SNS()::withMessage)
                .map(new SNSEvent.SNSRecord()::withSns)
                .map(List::of)
                .map(new SNSEvent()::withRecords)
                .get();
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
}
