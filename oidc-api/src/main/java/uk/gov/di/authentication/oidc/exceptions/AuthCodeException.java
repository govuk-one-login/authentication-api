package uk.gov.di.authentication.oidc.exceptions;

public class AuthCodeException extends Exception {
    public AuthCodeException(String message) {
        super(message);
    }
}
