package uk.gov.di.orchestration.shared.exceptions;

import com.nimbusds.oauth2.sdk.ErrorObject;

public class InvalidRedirectUriException extends Exception {
    private final ErrorObject error;

    public InvalidRedirectUriException(ErrorObject error) {
        this.error = error;
    }

    public ErrorObject getErrorObject() {
        return error;
    }
}
