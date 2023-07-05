package uk.gov.di.authentication.shared.exceptions;

public class SSMParameterNotFoundException extends RuntimeException {

    public SSMParameterNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
