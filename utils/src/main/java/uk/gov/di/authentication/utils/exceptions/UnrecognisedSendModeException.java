package uk.gov.di.authentication.utils.exceptions;

import static java.lang.String.format;

public class UnrecognisedSendModeException extends RuntimeException {
    public UnrecognisedSendModeException(String bulkEmailUserSendMode) {
        super(format("Didn't recognise send mode %s", bulkEmailUserSendMode));
    }
}
