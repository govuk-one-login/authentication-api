package uk.gov.di.authentication.oidc.exceptions;

import com.nimbusds.oauth2.sdk.ErrorObject;

public class InvalidAuthorizeRequestException extends Exception {

    private final ErrorObject error;

    public InvalidAuthorizeRequestException(ErrorObject error) {
        super(error != null ? error.getDescription() : null);
        this.error = error;
    }

    public ErrorObject getError() {
        return error;
    }
}
