package uk.gov.di.authentication.shared.exceptions;

public class ClientRegistryValidationException extends RuntimeException {
    public ClientRegistryValidationException(String message) {
        super(message);
    }
}
