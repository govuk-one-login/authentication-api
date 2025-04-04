package uk.gov.di.authentication.oidc.exceptions;

public class BackChannelLogoutPostRequestException extends RuntimeException {
    public BackChannelLogoutPostRequestException(String message) {
        super(message);
    }
}
