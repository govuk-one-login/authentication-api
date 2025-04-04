package uk.gov.di.authentication.oidc.exceptions;

public class PostRequestFailureException extends RuntimeException {
    public PostRequestFailureException(String message) {
        super(message);
    }
}
