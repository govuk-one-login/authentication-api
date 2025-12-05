package uk.gov.di.authentication.frontendapi.exceptions;

import com.nimbusds.oauth2.sdk.ErrorObject;

public class JarValidationException extends Exception {
    private final ErrorObject errorObject;

    public JarValidationException(ErrorObject errorObject) {
        super(errorObject.getDescription());
        this.errorObject = errorObject;
    }

    public JarValidationException(ErrorObject errorObject, Throwable cause) {
        super(errorObject.getDescription(), cause);
        this.errorObject = errorObject;
    }

    public ErrorObject getErrorObject() {
        return errorObject;
    }
}
