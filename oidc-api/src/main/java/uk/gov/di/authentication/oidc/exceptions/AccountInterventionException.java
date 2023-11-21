package uk.gov.di.authentication.oidc.exceptions;

public class AccountInterventionException extends RuntimeException {
    public AccountInterventionException(String message, Exception cause) {
        super(message, cause);
    }
}
