package uk.gov.di.orchestration.shared.exceptions;

public class JwtParseException extends RuntimeException {
    public JwtParseException(String message, Throwable cause) {
        super(message, cause);
    }
}
