package uk.gov.di.authentication.oidc.exceptions;

public class InvalidJWEException extends RuntimeException {
    public InvalidJWEException(String message, Throwable cause) {
        super(message, cause);
    }
}
