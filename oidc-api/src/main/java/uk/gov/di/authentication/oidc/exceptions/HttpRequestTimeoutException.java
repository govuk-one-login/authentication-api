package uk.gov.di.authentication.oidc.exceptions;

import java.io.IOException;

public class HttpRequestTimeoutException extends IOException {
    public HttpRequestTimeoutException(String message, Throwable cause) {
        super(message, cause);
    }
}
