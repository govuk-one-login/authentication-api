package uk.gov.di.orchestration.shared.tracing;

import uk.gov.di.orchestration.shared.annotations.ExcludeFromGeneratedCoverageReport;

import static java.util.Objects.nonNull;

@ExcludeFromGeneratedCoverageReport
public class Tracing {
    // This property is set by AWS Lambda when the function is invoked by an AWS service. It's *NOT*
    // set while the constructor is running.
    private static final String traceHeaderProperty = "com.amazonaws.xray.traceHeader";

    public static Boolean isOtelTracingAllowed() {
        return nonNull(System.getProperty(traceHeaderProperty));
    }
}
