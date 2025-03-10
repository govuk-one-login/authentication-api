package uk.gov.di.authentication.shared.exceptions;

public class UnknownMfaTypeException extends RuntimeException {
    public UnknownMfaTypeException(String message) {
        super(message);
    }
}
