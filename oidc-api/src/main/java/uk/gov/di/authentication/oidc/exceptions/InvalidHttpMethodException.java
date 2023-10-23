package uk.gov.di.authentication.oidc.exceptions;

public class InvalidHttpMethodException extends RuntimeException {
    public InvalidHttpMethodException(String message) {
        super(message);
    }
}
