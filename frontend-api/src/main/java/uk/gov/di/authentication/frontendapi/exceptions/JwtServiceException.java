package uk.gov.di.authentication.frontendapi.exceptions;

public class JwtServiceException extends RuntimeException {

    public JwtServiceException(String message) {
        super(message);
    }

    public JwtServiceException(String message, Throwable cause) {
        super(message, cause);
    }
}
