package uk.gov.di.accountmanagement.exceptions;

public class RecentlyActiveAccountException extends RuntimeException {
    public RecentlyActiveAccountException(String message) {
        super(message);
    }
}
