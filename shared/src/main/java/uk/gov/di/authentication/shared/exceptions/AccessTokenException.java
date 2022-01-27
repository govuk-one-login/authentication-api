package uk.gov.di.authentication.shared.exceptions;

import com.nimbusds.oauth2.sdk.ErrorObject;

public class AccessTokenException extends Exception {

    private final ErrorObject error;

    public AccessTokenException(String message, ErrorObject error) {
        super(message);
        this.error = error;
    }

    public ErrorObject getError() {
        return error;
    }
}
