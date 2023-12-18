package uk.gov.di.orchestration.shared.exceptions;

public class AccountInterventionException extends RuntimeException {

    public AccountInterventionException(String message) {
        super(message);
    }

    public AccountInterventionException(String message, Exception cause) {
        super(message, cause);
    }
}
