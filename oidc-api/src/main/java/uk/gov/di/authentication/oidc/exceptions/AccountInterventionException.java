package uk.gov.di.authentication.oidc.exceptions;

public class AccountInterventionException extends RuntimeException {
    public AccountInterventionException(Exception cause) {
        super(cause);
    }
}
