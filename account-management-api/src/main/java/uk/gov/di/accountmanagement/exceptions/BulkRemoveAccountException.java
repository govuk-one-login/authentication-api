package uk.gov.di.accountmanagement.exceptions;

public class BulkRemoveAccountException extends RuntimeException {
    public BulkRemoveAccountException(String message, Throwable cause) {
        super(message, cause);
    }

    public BulkRemoveAccountException(String message) {
        super(message);
    }
}
