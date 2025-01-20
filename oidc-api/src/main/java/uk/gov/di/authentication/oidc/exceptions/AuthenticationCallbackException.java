package uk.gov.di.authentication.oidc.exceptions;

public class AuthenticationCallbackException extends RuntimeException {
    public AuthenticationCallbackException(String message) {
        super(message);
    }

    public AuthenticationCallbackException(String message, Throwable cause) {
        super(message, cause);
    }
}
