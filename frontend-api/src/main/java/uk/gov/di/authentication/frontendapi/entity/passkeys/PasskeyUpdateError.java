package uk.gov.di.authentication.frontendapi.entity.passkeys;

public enum PasskeyUpdateError {
    PASSKEY_UPDATE_BAD_REQUEST("Passkey update bad request"),
    PASSKEY_UPDATE_UNAUTHORISED("Passkey update unauthorised request"),
    PASSKEY_OR_USER_NOT_FOUND("Passkey or user not found"),
    PASSKEY_UPDATE_INTERNAL_SERVER_ERROR("Passkey update account data api internal server error"),
    PASSKEY_UPDATE_UNEXPECTED_RESPONSE_CODE(
            "Account data api returned unexpected response code for update passkeys");

    private final String value;

    PasskeyUpdateError(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
