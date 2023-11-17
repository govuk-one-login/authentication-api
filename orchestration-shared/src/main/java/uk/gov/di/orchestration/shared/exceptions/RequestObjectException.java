package uk.gov.di.orchestration.shared.exceptions;

public class RequestObjectException extends RuntimeException {
    public RequestObjectException(String message, Throwable cause) {
        super(message, cause);
    }
}
