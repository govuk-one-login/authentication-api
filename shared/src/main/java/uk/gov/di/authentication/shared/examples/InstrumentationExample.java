package uk.gov.di.authentication.shared.examples;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.annotations.Instrumented;

/** Example class demonstrating the usage of @Instrumented annotation. */
public class InstrumentationExample {
    private static final Logger LOG = LogManager.getLogger(InstrumentationExample.class);

    /**
     * Example method using the instrumentation annotation with a default segment name. The segment
     * name will be "InstrumentationExample::methodWithDefaultSegmentName".
     */
    @Instrumented
    public String methodWithDefaultSegmentName(String input) {
        LOG.info("Processing in methodWithDefaultSegmentName");
        // Simulate some processing
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return "Processed: " + input;
    }

    /**
     * Example method using the instrumentation annotation with a custom segment name. The segment
     * name will be "CustomSegmentName".
     */
    @Instrumented("CustomSegmentName")
    public String methodWithCustomSegmentName(String input) {
        LOG.info("Processing in methodWithCustomSegmentName");
        // Simulate some processing
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return "Processed: " + input;
    }

    @Instrumented
    public static void staticMethod() {
        LOG.info("This static method has no arguments");
        // Simulate some processing
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** Method that doesn't use the annotation - will not be automatically instrumented. */
    public void nonInstrumentedMethod() {
        LOG.info("This method is not automatically instrumented");
    }
}
