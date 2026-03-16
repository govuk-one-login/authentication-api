package uk.gov.di.authentication.frontendapi.entity.passkeys;

public enum PasskeyRetrieveError {
    ERROR_RESPONSE_FROM_PASSKEY_RETRIEVE("Error response from retrieve passkeys endpoint");

    private final String value;

    PasskeyRetrieveError(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
