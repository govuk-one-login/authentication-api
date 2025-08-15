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
    JOURNEY_TYPE("JourneyType"),
    FAILURE_REASON("FailureReason"),
    IPV_RESPONSE("IpvResponse"),
    MFA_METHOD_TYPE("MfaMethodType"),
    MFA_METHOD_PRIORITY_IDENTIFIER("MfaMethodPriorityIdentifier"),
    APPLICATION("Application"),
    NOTIFICATION_TYPE("NotificationType"),
    COUNTRY("Country"),
    NOTIFICATION_HTTP_ERROR("NotificationHttpError");

    private String value;

    CloudwatchMetricDimensions(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
