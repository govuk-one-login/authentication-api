package uk.gov.di.authentication.shared.exceptions;

public class UnsuccessfulReverificationResponseException extends Exception {
    public UnsuccessfulReverificationResponseException(String message) {
        super(message);
    }
}
