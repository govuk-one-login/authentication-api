package uk.gov.di.authentication.utils.exceptions;

public class ChainedParallelScanException extends RuntimeException {
    public ChainedParallelScanException(String message) {
        super(message);
    }

    public ChainedParallelScanException(String message, Throwable cause) {
        super(message, cause);
    }
}
