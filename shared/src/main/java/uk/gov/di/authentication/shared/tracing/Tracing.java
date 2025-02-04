package uk.gov.di.authentication.shared.tracing;

import uk.gov.di.authentication.shared.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class Tracing {
    public static final Boolean TRACING_ENABLED =
            Boolean.valueOf(System.getenv().getOrDefault("TRACING_ENABLED", "true"));
}
