package uk.gov.di.authentication.shared.exceptions;

public class HttpRequestErrorException extends RuntimeException {
    public HttpRequestErrorException(int message) {
        super(String.valueOf(message));
    }
}
