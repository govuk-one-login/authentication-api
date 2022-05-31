package uk.gov.di.authentication.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.cloudwatchlogs.emf.logger.MetricsLogger;
import software.amazon.cloudwatchlogs.emf.model.DimensionSet;
import software.amazon.cloudwatchlogs.emf.model.Unit;

import java.util.Map;

import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class CloudwatchMetricsService {

    private static final Logger LOG = LogManager.getLogger(CloudwatchMetricsService.class);
    private static final MetricsLogger metrics = new MetricsLogger();

    public CloudwatchMetricsService() {}

    public static void putEmbeddedValue(String name, double value, Map<String, String> dimensions) {
        segmentedFunctionCall(
                "Metrics::EMF",
                () -> {
                    var dimensionsSet = new DimensionSet();

                    dimensions.forEach(dimensionsSet::addDimension);

                    metrics.setNamespace("Authentication");
                    metrics.putDimensions(dimensionsSet);
                    metrics.putMetric(name, value, Unit.NONE);
                    metrics.flush();
                });
    }

    public void incrementCounter(String name, Map<String, String> dimensions) {
        putEmbeddedValue(name, 1, dimensions);
    }
}
