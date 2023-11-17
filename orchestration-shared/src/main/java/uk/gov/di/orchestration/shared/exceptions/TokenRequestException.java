package uk.gov.di.orchestration.shared.exceptions;

public class TokenRequestException extends RuntimeException {
    public TokenRequestException(String message, Throwable cause) {
        super(message, cause);
    }
}
