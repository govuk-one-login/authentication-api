package uk.gov.di.authentication.shared.exceptions;

public class UnsuccesfulCredentialResponseException extends Exception {
    public UnsuccesfulCredentialResponseException(String message) {
        super(message);
    }

    public UnsuccesfulCredentialResponseException(String message, Throwable cause) {
        super(message, cause);
    }
}
