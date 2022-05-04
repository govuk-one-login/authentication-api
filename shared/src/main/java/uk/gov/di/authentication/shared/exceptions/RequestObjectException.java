package uk.gov.di.authentication.shared.exceptions;

public class RequestObjectException extends RuntimeException {
    public RequestObjectException(String message, Throwable cause) {
        super(message, cause);
    }
}
