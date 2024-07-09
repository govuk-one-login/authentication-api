package uk.gov.di.orchestration.shared.exceptions;

public class ClientRedirectUriValidationException extends RuntimeException {
    public ClientRedirectUriValidationException(String message) {
        super(message);
    }
}
