package uk.gov.di.authentication.oidc.exceptions;

public class AuthenticationAuthorisationRequestException extends Exception {
    public AuthenticationAuthorisationRequestException(String message) {
        super(message);
    }

    public AuthenticationAuthorisationRequestException(String message, Throwable cause) {
        super(message, cause);
    }
}
