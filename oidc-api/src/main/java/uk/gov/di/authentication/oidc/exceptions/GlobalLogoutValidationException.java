package uk.gov.di.authentication.oidc.exceptions;

public class GlobalLogoutValidationException extends RuntimeException {
    public GlobalLogoutValidationException(String message) {
        super(message);
    }
}
