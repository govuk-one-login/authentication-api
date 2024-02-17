package uk.gov.di.authentication.shared.exceptions;

import java.io.IOException;
import java.net.http.HttpTimeoutException;

import static java.lang.String.format;

public class UnsuccessfulAccountInterventionsResponseException extends Exception {

    private final int httpCode;

    public UnsuccessfulAccountInterventionsResponseException(String message, int code) {
        super(message);
        this.httpCode = code;
    }

    public UnsuccessfulAccountInterventionsResponseException(String message, Throwable cause) {
        super(message, cause);
        this.httpCode = 0;
    }

    public static UnsuccessfulAccountInterventionsResponseException ioException(IOException e) {
        return new UnsuccessfulAccountInterventionsResponseException(
                "Error when attempting to call Account Interventions outbound endpoint", e);
    }

    public static UnsuccessfulAccountInterventionsResponseException interruptedException(
            InterruptedException e) {
        return new UnsuccessfulAccountInterventionsResponseException(
                "Interrupted exception when attempting to call Account Interventions outbound endpoint",
                e);
    }

    public static UnsuccessfulAccountInterventionsResponseException timeoutException(
            Long timeout, HttpTimeoutException e) {

        return new UnsuccessfulAccountInterventionsResponseException(
                format(
                        "Timeout when calling Account Interventions endpoint with timeout of %d",
                        timeout),
                e);
    }

    public static UnsuccessfulAccountInterventionsResponseException httpResponseCodeException(
            Integer statusCode, Object body) {
        return new UnsuccessfulAccountInterventionsResponseException(
                format(
                        "Error %s when attempting to call Account Interventions outbound endpoint: %s",
                        statusCode, body),
                statusCode);
    }

    public static UnsuccessfulAccountInterventionsResponseException parseException(Exception e) {
        return new UnsuccessfulAccountInterventionsResponseException(
                "Error parsing HTTP response", e);
    }

    public int getHttpCode() {
        return httpCode;
    }
}
