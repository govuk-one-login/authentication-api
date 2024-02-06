package uk.gov.di.authentication.shared.exceptions;

public class CodeRequestTypeNotFoundException extends RuntimeException {
    public CodeRequestTypeNotFoundException(String message) {
        super(message);
    }
}
