package uk.gov.di.orchestration.shared.exceptions;

public class TokenResponseException extends RuntimeException {
    public TokenResponseException(String message, Throwable cause) {
        super(message, cause);
    }
}
