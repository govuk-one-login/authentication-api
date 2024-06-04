package uk.gov.di.orchestration.shared.exceptions;

import com.nimbusds.oauth2.sdk.ErrorObject;

public class ClientRegistrryConfigValidationException extends Exception {

    private final ErrorObject errorObject;

    public ClientRegistrryConfigValidationException(ErrorObject errorObject) {
        super(errorObject.getDescription());
        this.errorObject = errorObject;
    }

    public ErrorObject getErrorObject() {
        return errorObject;
    }
}
