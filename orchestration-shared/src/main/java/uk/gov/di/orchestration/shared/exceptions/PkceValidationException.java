package uk.gov.di.orchestration.shared.exceptions;

public class PkceValidationException extends RuntimeException {
    public PkceValidationException(String message) {
        super(message);
    }
}
