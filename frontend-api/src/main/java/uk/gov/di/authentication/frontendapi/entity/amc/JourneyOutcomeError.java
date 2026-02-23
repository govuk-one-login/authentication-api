package uk.gov.di.authentication.frontendapi.entity.amc;

public enum JourneyOutcomeError {
    ERROR_RESPONSE_FROM_JOURNEY_OUTCOME("Error response from journey outcome request"),
    IO_EXCEPTION("IO Exception when attempting to retrieve journey outcome");

    private final String value;

    JourneyOutcomeError(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
