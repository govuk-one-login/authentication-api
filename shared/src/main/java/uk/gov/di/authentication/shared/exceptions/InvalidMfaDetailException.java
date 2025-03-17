package uk.gov.di.authentication.shared.exceptions;

public class InvalidMfaDetailException extends Exception {
    public InvalidMfaDetailException(String message) {
        super(message);
    }
}
