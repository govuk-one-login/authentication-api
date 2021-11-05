package uk.gov.di.authentication.sharedtest.logging;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.List;

public class CaptureLoggingExtension implements BeforeEachCallback, AfterEachCallback {

    private final StubAppender appender = new StubAppender();
    private final Class<?> classUnderTest;

    public CaptureLoggingExtension(Class<?> classUnderTest) {
        this.classUnderTest = classUnderTest;
    }

    @Override
    public void afterEach(ExtensionContext context) {
        Logger logger = (Logger) LogManager.getLogger(classUnderTest);
        logger.removeAppender(appender);
    }

    @Override
    public void beforeEach(ExtensionContext context) throws Exception {
        Logger logger = (Logger) LogManager.getLogger(classUnderTest);

        appender.start();
        logger.addAppender(appender);
    }

    public List<LogEvent> events() {
        return appender.getEvents();
    }
}
