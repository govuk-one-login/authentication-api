package uk.gov.di.authentication.accountdata.entity;

public class UnauthorizedException extends RuntimeException {
    private static final String UNAUTHORIZED_STRING = "Unauthorized";

    public UnauthorizedException() {
        super(UNAUTHORIZED_STRING);
    }
}
