package uk.gov.di.authentication.shared.services;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.logging.log4j.core.LogEvent;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import software.amazon.cloudwatchlogs.emf.logger.MetricsLogger;
import software.amazon.cloudwatchlogs.emf.model.DimensionSet;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static uk.gov.di.authentication.shared.entity.JourneyType.ACCOUNT_MANAGEMENT;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class CloudwatchMetricsServiceTest {

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(CloudwatchMetricsService.class);

    @Nested
    class GetDimensions {
        @Test
        void shouldAlwaysIncludeEnvironmentDimensionFromConfiguration() {
            var randomEnvironment = RandomStringUtils.secure().nextAlphanumeric(10);

            var service =
                    new CloudwatchMetricsService(configurationWithEnvironment(randomEnvironment));

            var dimensions = service.getDimensions(Collections.emptyMap());

            assertThat(dimensions.getDimensionKeys().size(), is(1));
            assertThat(dimensions.getDimensionValue("Environment"), is(randomEnvironment));
        }

        @Nested
        class EmitMetric {
            @Test
            void shouldEmitMetricWithNamespace() {
                var service = new CloudwatchMetricsService(configurationWithEnvironment("test"));
                var metricsLogger = Mockito.mock(MetricsLogger.class);

                service.emitMetric("Metric", 1, Collections.emptyMap(), metricsLogger);

                verify(metricsLogger).setNamespace("Authentication");
            }

            @Test
            void shouldEmitMetricWithDimensions() {
                var dimensionSet = ArgumentCaptor.forClass(DimensionSet.class);
                var metricsLogger = Mockito.mock(MetricsLogger.class);

                var service = new CloudwatchMetricsService(configurationWithEnvironment("test"));

                service.emitMetric("Metric", 1, Map.of("Key1", "Value1"), metricsLogger);

                verify(metricsLogger).putDimensions(dimensionSet.capture());

                assertThat(dimensionSet.getValue().getDimensionValue("Key1"), is("Value1"));
                assertThat(dimensionSet.getValue().getDimensionKeys().size(), is(1));
            }

            @Test
            void shouldEmitMetricCatchValidationExceptions() {
                var metricsLogger = new MetricsLogger();
                var service = new CloudwatchMetricsService(configurationWithEnvironment("test"));

                service.emitMetric(
                        new String(new char[2000]).replace('\0', 'A'),
                        1,
                        Map.of("Key1", "Value1"),
                        metricsLogger);
                service.emitMetric("Metric", 1, Map.of("Key1", ""), metricsLogger);
                service.emitMetric("Metric", 1, Map.of("", "Value1"), metricsLogger);

                List<LogEvent> events = logging.events();
                assertThat(
                        events,
                        hasItem(
                                withMessageContaining(
                                        "Error emitting metric: Metric name exceeds maximum length of 1024")));
                assertThat(
                        events,
                        hasItem(
                                withMessageContaining(
                                        "Error emitting metric: Dimension value cannot be empty")));
                assertThat(
                        events,
                        hasItem(
                                withMessageContaining(
                                        "Error emitting metric: Dimension name cannot be empty")));
                assertEquals(3, events.size());
            }
        }

        @Nested
        class IncrementMfaMethodCounter {
            @Test
            void shouldIncrementMfaMethodCounterWithCorrectDimensions1() {
                var spyService = Mockito.spy(CloudwatchMetricsService.class);

                spyService.incrementMfaMethodCounter(
                        "SomeMfaMethodName",
                        "test",
                        "SomeOperation",
                        "SomeResult",
                        ACCOUNT_MANAGEMENT,
                        MFAMethodType.AUTH_APP);

                var expectedDimensions =
                        Map.of(
                                "Environment",
                                "test",
                                "Operation",
                                "SomeOperation",
                                "Result",
                                "SomeResult",
                                "JourneyType",
                                "ACCOUNT_MANAGEMENT",
                                "MfaMethodType",
                                "AUTH_APP");

                verify(spyService).putEmbeddedValue("SomeMfaMethodName", 1, expectedDimensions);
            }
        }

        private static ConfigurationService configurationWithEnvironment(String test) {
            return new ConfigurationService() {
                @Override
                public String getEnvironment() {
                    return test;
                }
            };
        }
    }
}
