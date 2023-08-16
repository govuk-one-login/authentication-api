package uk.gov.di.authentication.shared.exceptions;

public class UnsuccessfulCredentialResponseException extends Exception {

    private final int httpCode;

    public UnsuccessfulCredentialResponseException(String message) {
        super(message);
        this.httpCode = 0;
    }

    public UnsuccessfulCredentialResponseException(String message, int code) {
        super(message);
        this.httpCode = code;
    }

    public UnsuccessfulCredentialResponseException(String message, Throwable cause) {
        super(message, cause);
        this.httpCode = 0;
    }

    public int getHttpCode() {
        return httpCode;
    }
}
