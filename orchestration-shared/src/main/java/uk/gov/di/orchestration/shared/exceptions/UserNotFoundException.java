package uk.gov.di.orchestration.shared.exceptions;

public class UserNotFoundException extends Exception {

    public UserNotFoundException(String message) {
        super(message);
    }
}
