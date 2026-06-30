package uk.gov.di.orchestration.shared.exceptions;

public class InvalidJWEException extends RuntimeException {
    public InvalidJWEException(String message, Throwable cause) {
        super(message, cause);
    }
}
