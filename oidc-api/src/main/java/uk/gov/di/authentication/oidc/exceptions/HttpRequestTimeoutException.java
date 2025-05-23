package uk.gov.di.authentication.oidc.exceptions;

public class HttpRequestTimeoutException extends RuntimeException {
    public HttpRequestTimeoutException(String message, Throwable cause) {
        super(message, cause);
    }
}
