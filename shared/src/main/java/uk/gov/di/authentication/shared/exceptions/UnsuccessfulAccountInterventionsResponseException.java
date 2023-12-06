package uk.gov.di.authentication.shared.exceptions;

public class UnsuccessfulAccountInterventionsResponseException extends Exception {

    private final int httpCode;

    public UnsuccessfulAccountInterventionsResponseException(String message, int code) {
        super(message);
        this.httpCode = code;
    }

    public UnsuccessfulAccountInterventionsResponseException(String message, Throwable cause) {
        super(message, cause);
        this.httpCode = 0;
    }

    public int getHttpCode() {
        return httpCode;
    }
}
