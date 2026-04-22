package uk.gov.di.authentication.frontendapi.entity.passkeys;

public enum PasskeyRetrieveError {
    ERROR_RESPONSE_FROM_PASSKEY_RETRIEVE("Error response from retrieve passkeys endpoint"),
    ERROR_PARSING_RESPONSE_FROM_PASSKEY_RETRIEVE(
            "Error parsing response from retrieve passkeys endpoint"),
    IO_EXCEPTION("IO Exception when attempting to retrieve passkeys"),
    INTERRUPTED_EXCEPTION("Interrupted exception when attempting to retrieve passkeys"),
    ERROR_CREATING_ACCESS_TOKEN("Error creating access token");

    private final String value;

    PasskeyRetrieveError(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
