package uk.gov.di.authentication.oidc.exceptions;

public class UserInfoException extends RuntimeException {
    public UserInfoException(String message) {
        super(message);
    }
}
