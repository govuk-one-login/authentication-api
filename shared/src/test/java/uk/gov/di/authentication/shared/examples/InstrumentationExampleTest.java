package uk.gov.di.authentication.shared.examples;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import uk.gov.di.authentication.shared.helpers.InstrumentationHelper;

import java.util.concurrent.Callable;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;

class InstrumentationExampleTest {

    private InstrumentationExample instrumentationExample;

    @BeforeEach
    void setUp() {
        instrumentationExample = new InstrumentationExample();
    }

    @Test
    void shouldCallSegmentedFunctionCallForMethodWithDefaultSegmentName() {
        // This test verifies that the @Instrumented annotation triggers the aspect
        // to call InstrumentationHelper.segmentedFunctionCall with the default segment name

        try (MockedStatic<InstrumentationHelper> mockedStatic =
                mockStatic(InstrumentationHelper.class)) {
            // Set up the mock to pass through the call to the actual method
            mockedStatic
                    .<String>when(
                            () ->
                                    InstrumentationHelper.segmentedFunctionCall(
                                            eq(
                                                    "InstrumentationExample::methodWithDefaultSegmentName"),
                                            any(Callable.class)))
                    .thenAnswer(
                            invocation -> {
                                Callable<?> callable = invocation.getArgument(1);
                                return callable.call();
                            });

            // Call the method
            String result = instrumentationExample.methodWithDefaultSegmentName("test-input");

            // Verify the result is as expected
            assertEquals("Processed: test-input", result);

            // Verify that segmentedFunctionCall was called with the default segment name
            mockedStatic.verify(
                    () ->
                            InstrumentationHelper.<String>segmentedFunctionCall(
                                    eq("InstrumentationExample::methodWithDefaultSegmentName"),
                                    any(Callable.class)));
        }
    }

    @Test
    void shouldCallSegmentedFunctionCallForMethodWithCustomSegmentName() {
        // This test verifies that the @Instrumented annotation with custom value
        // triggers the aspect to call InstrumentationHelper.segmentedFunctionCall with that custom
        // segment name

        try (MockedStatic<InstrumentationHelper> mockedStatic =
                mockStatic(InstrumentationHelper.class)) {
            // Set up the mock to pass through the call to the actual method
            mockedStatic
                    .<String>when(
                            () ->
                                    InstrumentationHelper.segmentedFunctionCall(
                                            eq("CustomSegmentName"), any(Callable.class)))
                    .thenAnswer(
                            invocation -> {
                                Callable<?> callable = invocation.getArgument(1);
                                return callable.call();
                            });

            // Call the method
            String result = instrumentationExample.methodWithCustomSegmentName("test-input");

            // Verify the result is as expected
            assertEquals("Processed: test-input", result);

            // Verify that segmentedFunctionCall was called with the default segment name
            mockedStatic.verify(
                    () ->
                            InstrumentationHelper.<String>segmentedFunctionCall(
                                    eq("CustomSegmentName"), any(Callable.class)));
        }
    }

    @Test
    void shouldNotCallSegmentedFunctionCallForNonInstrumentedMethod() {
        // This test verifies that methods without @Instrumented annotation
        // do not trigger calls to InstrumentationHelper.segmentedFunctionCall

        try (MockedStatic<InstrumentationHelper> mockedStatic =
                mockStatic(InstrumentationHelper.class)) {
            // Call the method that's not instrumented
            instrumentationExample.nonInstrumentedMethod();

            // Verify that segmentedFunctionCall was not called at all
            mockedStatic.verifyNoInteractions();
        }
    }
}
