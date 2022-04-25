package uk.gov.di.authentication.app.exception;

public class UnsuccesfulCredentialResponseException extends RuntimeException {
    public UnsuccesfulCredentialResponseException(String message) {
        super(message);
    }

    public UnsuccesfulCredentialResponseException(String message, Throwable cause) {
        super(message, cause);
    }
}
