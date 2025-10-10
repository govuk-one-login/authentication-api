package uk.gov.di.orchestration.shared.domain;

public enum CloudwatchMetricDimensions {
    ACCOUNT("Account"),
    ENVIRONMENT("Environment"),
    CLIENT("Client"),
    REQUESTED_LEVEL_OF_CONFIDENCE("RequestedLevelOfConfidence"),
    MFA_REQUIRED("MfaRequired"),
    CLIENT_NAME("ClientName"),
    ACCOUNT_INTERVENTION_STATE("AccountInterventionState");

    private String value;

    CloudwatchMetricDimensions(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
