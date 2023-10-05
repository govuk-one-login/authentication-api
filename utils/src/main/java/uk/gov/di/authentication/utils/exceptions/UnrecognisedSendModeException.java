package uk.gov.di.authentication.utils.exceptions;

public class UnrecognisedSendModeException extends RuntimeException {
    public UnrecognisedSendModeException(String message) {
        super(message);
    }
}
