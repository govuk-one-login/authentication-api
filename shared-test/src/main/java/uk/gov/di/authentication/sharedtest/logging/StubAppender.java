package uk.gov.di.authentication.sharedtest.logging;

import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class StubAppender extends AbstractAppender {

    final List<LogEvent> events = Collections.synchronizedList(new ArrayList<>());

    public StubAppender() {
        super("StubAppender", null, null, true, Property.EMPTY_ARRAY);
    }

    @Override
    public void append(final LogEvent event) {
        events.add(event.toImmutable());
    }

    public List<LogEvent> getEvents() {
        return events;
    }
}
