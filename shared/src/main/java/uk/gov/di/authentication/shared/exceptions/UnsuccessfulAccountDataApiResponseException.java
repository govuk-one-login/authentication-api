package uk.gov.di.authentication.shared.exceptions;

import java.io.IOException;
import java.net.http.HttpTimeoutException;

import static java.lang.String.format;

public class UnsuccessfulAccountDataApiResponseException extends Exception {

    private final int httpCode;

    public UnsuccessfulAccountDataApiResponseException(String message, int code) {
        super(message);
        this.httpCode = code;
    }

    public UnsuccessfulAccountDataApiResponseException(String message, Throwable cause) {
        super(message, cause);
        this.httpCode = 0;
    }

    public static UnsuccessfulAccountDataApiResponseException ioException(IOException e) {
        return new UnsuccessfulAccountDataApiResponseException(
                "Error when attempting to call Account Data API outbound endpoint", e);
    }

    public static UnsuccessfulAccountDataApiResponseException interruptedException(
            InterruptedException e) {
        return new UnsuccessfulAccountDataApiResponseException(
                "Interrupted exception when attempting to call Account Data API outbound endpoint",
                e);
    }

    public static UnsuccessfulAccountDataApiResponseException timeoutException(
            Long timeout, HttpTimeoutException e) {

        return new UnsuccessfulAccountDataApiResponseException(
                format(
                        "Timeout when calling Account Data API endpoint with timeout of %d",
                        timeout),
                e);
    }

    public static UnsuccessfulAccountDataApiResponseException httpResponseCodeException(
            Integer statusCode, Object body) {
        return new UnsuccessfulAccountDataApiResponseException(
                format(
                        "Error %s when attempting to call Account Data API outbound endpoint: %s",
                        statusCode, body),
                statusCode);
    }

    public static UnsuccessfulAccountDataApiResponseException parseException(Exception e) {
        return new UnsuccessfulAccountDataApiResponseException("Error parsing HTTP response", e);
    }

    public int getHttpCode() {
        return httpCode;
    }
}
