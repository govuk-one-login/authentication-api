package uk.gov.di.orchestration.shared.exceptions;

public class StateStorageException extends RuntimeException {
    public StateStorageException(String message) {
        super(message);
    }
}
