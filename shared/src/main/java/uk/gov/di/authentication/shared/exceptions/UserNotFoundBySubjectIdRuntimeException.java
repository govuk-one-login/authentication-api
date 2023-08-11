package uk.gov.di.authentication.shared.exceptions;

public class UserNotFoundBySubjectIdRuntimeException extends RuntimeException {

    public UserNotFoundBySubjectIdRuntimeException(String message) {
        super(message);
    }
}
