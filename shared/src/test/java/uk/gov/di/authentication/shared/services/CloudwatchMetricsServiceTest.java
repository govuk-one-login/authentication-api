package uk.gov.di.authentication.shared.services;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import software.amazon.cloudwatchlogs.emf.logger.MetricsLogger;
import software.amazon.cloudwatchlogs.emf.model.DimensionSet;

import java.util.Collections;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class CloudwatchMetricsServiceTest {

    @Test
    void shouldAlwaysIncludeEnvironmentDimensionFromConfiguration() {
        var randomEnvironment = RandomStringUtils.secure().nextAlphanumeric(10);

        var service = new CloudwatchMetricsService(configurationWithEnvironment(randomEnvironment));

        var dimensions = service.getDimensions(Collections.emptyMap());

        assertThat(dimensions.getDimensionKeys().size(), is(1));
        assertThat(dimensions.getDimensionValue("Environment"), is(randomEnvironment));
    }

    @Test
    void shouldIncludeEnvironmentDimensionAndAllExtraDimensions() {
        var randomEnvironment = RandomStringUtils.secure().nextAlphanumeric(10);

        var service = new CloudwatchMetricsService(configurationWithEnvironment(randomEnvironment));

        var dimensions = service.getDimensions(Map.of("Key1", "Value1"));

        assertThat(dimensions.getDimensionKeys().size(), is(2));
        assertThat(dimensions.getDimensionValue("Environment"), is(randomEnvironment));
        assertThat(dimensions.getDimensionValue("Key1"), is("Value1"));
    }

    @Test
    void shouldEmitMetricWithNamespace() {
        var metricsLogger = Mockito.mock(MetricsLogger.class);

        var service = new CloudwatchMetricsService(configurationWithEnvironment("test"));

        service.emitMetric("Metric", 1, Collections.emptyMap(), metricsLogger);

        Mockito.verify(metricsLogger).setNamespace("Authentication");
    }

    @Test
    void shouldEmitMetricWithDimensions() {
        var metricsLogger = Mockito.mock(MetricsLogger.class);
        var dimensionSet = ArgumentCaptor.forClass(DimensionSet.class);

        var service = new CloudwatchMetricsService(configurationWithEnvironment("test"));

        service.emitMetric("Metric", 1, Map.of("Key1", "Value1"), metricsLogger);

        Mockito.verify(metricsLogger).putDimensions(dimensionSet.capture());

        assertThat(dimensionSet.getValue().getDimensionValue("Key1"), is("Value1"));
        assertThat(dimensionSet.getValue().getDimensionKeys().size(), is(1));
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
