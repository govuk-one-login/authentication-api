package uk.gov.di.authentication.shared.services;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.RandomUtils;
import org.junit.jupiter.api.Test;
import software.amazon.cloudwatchlogs.emf.model.DimensionSet;

import java.util.Collections;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class CloudwatchMetricsServiceTest {

    @Test
    void shouldAlwaysIncludeEnvironmentDimensionFromConfiguration() {
        var randomEnvironment = RandomStringUtils.secure().nextAlphanumeric(10);

        var service = new CloudwatchMetricsService(new ConfigurationService() {
            @Override
            public String getEnvironment() {
                return randomEnvironment;
            }
        });

        var dimensions = service.getDimensions(Collections.emptyMap());

        assertThat(dimensions.getDimensionKeys().size(), is(1));
        assertThat(dimensions.getDimensionValue("Environment"), is(randomEnvironment));
    }

}