package uk.gov.di.authentication.oidc.exceptions;

public class InvalidPublicKeyException extends RuntimeException {
    public InvalidPublicKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
