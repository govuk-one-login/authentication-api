package uk.gov.di.authentication.utils.exceptions;

public class IncludedTermsAndConditionsConfigMissingException extends RuntimeException {
    public IncludedTermsAndConditionsConfigMissingException() {
        super("Included terms and conditions configuration is missing");
    }
}
