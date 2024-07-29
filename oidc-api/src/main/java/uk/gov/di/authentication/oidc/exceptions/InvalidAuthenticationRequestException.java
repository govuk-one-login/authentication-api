package uk.gov.di.authentication.oidc.exceptions;

import com.nimbusds.oauth2.sdk.ErrorObject;

public class InvalidAuthenticationRequestException extends Exception {

    private final ErrorObject error;

    public InvalidAuthenticationRequestException(ErrorObject error) {
        this.error = error;
    }

    public ErrorObject getError() {
        return error;
    }
}
