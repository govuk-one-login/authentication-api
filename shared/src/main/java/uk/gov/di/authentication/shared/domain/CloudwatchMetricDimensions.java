package uk.gov.di.authentication.shared.domain;

public enum CloudwatchMetricDimensions {
    ACCOUNT("Account"),
    ENVIRONMENT("Environment"),
    CLIENT("Client"),
    IS_TEST("IsTest"),
    REQUESTED_LEVEL_OF_CONFIDENCE("RequestedLevelOfConfidence"),
    MFA_REQUIRED("MfaRequired"),
    CLIENT_NAME("ClientName"),
    CREDENTIAL_TYPE("CredentialType"),
    JOURNEY_TYPE("JourneyType");

    private String value;

    CloudwatchMetricDimensions(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
