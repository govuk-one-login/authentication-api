package uk.gov.di.orchestration.shared.exceptions;

public class ClientRegistryValidationException extends RuntimeException {
    public ClientRegistryValidationException(String message) {
        super(message);
    }
}
