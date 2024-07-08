package uk.gov.di.authentication.shared.exceptions;

public class ClientRedirectUriValidationException extends RuntimeException {
    public ClientRedirectUriValidationException(String message) {
        super(message);
    }
}
