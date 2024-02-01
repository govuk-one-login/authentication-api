package uk.gov.di.orchestration.shared.exceptions;

import com.nimbusds.oauth2.sdk.ErrorObject;

public class TokenAuthUnsupportedMethodException extends Exception {
    private final ErrorObject error;

    public TokenAuthUnsupportedMethodException(ErrorObject error) {
        this.error = error;
    }

    public ErrorObject getErrorObject() {
        return error;
    }
}
