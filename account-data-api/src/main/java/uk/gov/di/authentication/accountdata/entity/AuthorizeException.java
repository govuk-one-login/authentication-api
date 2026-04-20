package uk.gov.di.authentication.accountdata.entity;

public class AuthorizeException extends RuntimeException {
    public AuthorizeException(String e) {
        super(e);
    }
}
