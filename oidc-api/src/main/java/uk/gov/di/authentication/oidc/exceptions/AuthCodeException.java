package uk.gov.di.authentication.oidc.exceptions;

public class AuthCodeException extends RuntimeException {
    public AuthCodeException(String message) {
        super(message);
    }
}
