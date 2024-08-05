package uk.gov.di.authentication.oidc.exceptions;

import com.nimbusds.oauth2.sdk.ErrorObject;

public class MissingClientIDException extends Exception {

    private final ErrorObject error;

    public MissingClientIDException(ErrorObject error) {
        this.error = error;
    }

    public ErrorObject getError() {
        return error;
    }
}
