package uk.gov.di.authentication.shared.exceptions;

public class TokenRequestException extends RuntimeException {
    public TokenRequestException(String message, Throwable cause) {
        super(message, cause);
    }
}
