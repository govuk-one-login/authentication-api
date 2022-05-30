package uk.gov.di.authentication.shared.services;

import software.amazon.cloudwatchlogs.emf.logger.MetricsLogger;
import software.amazon.cloudwatchlogs.emf.model.DimensionSet;
import software.amazon.cloudwatchlogs.emf.model.Unit;

import java.util.Map;

import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class CloudwatchMetricsService {

    public CloudwatchMetricsService() {}

    public static void putEmbeddedValue(String name, double value, Map<String, String> dimensions) {
        segmentedFunctionCall(
                "Metrics::EMF",
                () -> {
                    var metrics = new MetricsLogger();
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
