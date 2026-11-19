package uk.gov.di.authentication.shared.exceptions;

public class AuthenticationAttemptsException extends RuntimeException {

    public AuthenticationAttemptsException(String message, Throwable cause) {
        super(message, cause);
    }
}
