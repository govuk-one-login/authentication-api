package uk.gov.di.authentication.utils.exceptions;

public class ExcludedTermsAndConditionsConfigMissingException extends RuntimeException {
    public ExcludedTermsAndConditionsConfigMissingException(String message) {
        super(message);
    }
}
