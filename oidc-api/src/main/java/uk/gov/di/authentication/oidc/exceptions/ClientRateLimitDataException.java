package uk.gov.di.authentication.oidc.exceptions;

public class ClientRateLimitDataException extends RuntimeException {
    public ClientRateLimitDataException(String message) {
        super(message);
    }
}
