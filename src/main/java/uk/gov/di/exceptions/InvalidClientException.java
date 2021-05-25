package uk.gov.di.exceptions;

public class InvalidClientException extends RuntimeException {

    public InvalidClientException(String message) {
        super(message);
    }
}
