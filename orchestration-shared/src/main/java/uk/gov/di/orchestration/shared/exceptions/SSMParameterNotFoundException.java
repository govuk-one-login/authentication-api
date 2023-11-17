package uk.gov.di.orchestration.shared.exceptions;

public class SSMParameterNotFoundException extends RuntimeException {

    public SSMParameterNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
