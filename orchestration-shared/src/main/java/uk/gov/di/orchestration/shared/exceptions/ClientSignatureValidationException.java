package uk.gov.di.orchestration.shared.exceptions;

public class ClientSignatureValidationException extends Exception {

    public ClientSignatureValidationException(String message) {
        super(message);
    }

    public ClientSignatureValidationException(Exception cause) {
        super(cause);
    }
}
