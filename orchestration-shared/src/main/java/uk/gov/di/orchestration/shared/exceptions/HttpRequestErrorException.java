package uk.gov.di.orchestration.shared.exceptions;

public class HttpRequestErrorException extends RuntimeException {
    private final int errorCode;

    public HttpRequestErrorException(int errorCode) {
        super(String.valueOf(errorCode));
        this.errorCode = errorCode;
    }

    public int getErrorCode() {
        return errorCode;
    }
}
