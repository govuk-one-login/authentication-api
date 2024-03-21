package uk.gov.di.authentication.frontendapi.exceptions;

import uk.gov.di.authentication.shared.entity.ErrorResponse;

public class AccountLockedException extends RuntimeException {
    private final ErrorResponse errorResponse;

    public AccountLockedException(String message, ErrorResponse errorResponse) {
        super(message);
        this.errorResponse = errorResponse;
    }

    public ErrorResponse getErrorResponse() {
        return this.errorResponse;
    }
}
