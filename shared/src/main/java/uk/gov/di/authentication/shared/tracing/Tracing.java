package uk.gov.di.authentication.shared.tracing;

import uk.gov.di.authentication.shared.annotations.ExcludeFromGeneratedCoverageReport;

import static java.util.Objects.nonNull;

@ExcludeFromGeneratedCoverageReport
public class Tracing {
    private static final String traceHeaderProperty = "com.amazonaws.xray.traceHeader";
    public static final Boolean TRACING_ENABLED =
            Boolean.valueOf(System.getenv().getOrDefault("TRACING_ENABLED", "true"));

    public static Boolean isTracingEnabled() {
        return TRACING_ENABLED;
    }

    public static Boolean isOtelTracingAllowed() {
        return nonNull(System.getProperty(traceHeaderProperty)) && isTracingEnabled();
    }
}
