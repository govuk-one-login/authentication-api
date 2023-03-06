package uk.gov.di.accountmanagement.exceptions;

public class MissingConfigurationParameterException extends RuntimeException {

    public MissingConfigurationParameterException(String message) {
        super(message);
    }
}
