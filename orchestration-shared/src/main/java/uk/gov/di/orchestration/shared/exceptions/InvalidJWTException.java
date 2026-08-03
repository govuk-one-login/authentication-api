package uk.gov.di.orchestration.shared.exceptions;

public class InvalidJWTException extends RuntimeException {
    public InvalidJWTException(String message, Throwable cause) {
        super(message, cause);
    }
}
