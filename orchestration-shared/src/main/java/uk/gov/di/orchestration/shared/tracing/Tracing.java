package uk.gov.di.orchestration.shared.tracing;

import uk.gov.di.orchestration.shared.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class Tracing {
    private static final String traceHeaderProperty = "com.amazonaws.xray.traceHeader";
    public static final Boolean TRACING_ENABLED =
            Boolean.valueOf(System.getenv().getOrDefault("TRACING_ENABLED", "true"));

    public static Boolean isTracingAllowed() {
        return System.getProperty(traceHeaderProperty) != null && TRACING_ENABLED;
    }
}
