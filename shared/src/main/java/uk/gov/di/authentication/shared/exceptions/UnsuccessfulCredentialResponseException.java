package uk.gov.di.authentication.shared.exceptions;

public class UnsuccessfulCredentialResponseException extends Exception {
    public UnsuccessfulCredentialResponseException(String message) {
        super(message);
    }

    public UnsuccessfulCredentialResponseException(String message, Throwable cause) {
        super(message, cause);
    }
}
