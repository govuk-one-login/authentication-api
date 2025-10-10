package uk.gov.di.authentication.oidc.exceptions;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;

public class AuthenticationCallbackValidationException extends Exception {

    private final ErrorObject error;
    private final boolean logoutRequired;

    public AuthenticationCallbackValidationException() {
        this(OAuth2Error.SERVER_ERROR, false);
    }

    public AuthenticationCallbackValidationException(ErrorObject error) {
        this(error, false);
    }

    public AuthenticationCallbackValidationException(ErrorObject error, boolean logoutRequired) {
        this.error = error;
        this.logoutRequired = logoutRequired;
    }

    public ErrorObject getError() {
        return error;
    }

    public boolean getLogoutRequired() {
        return logoutRequired;
    }
}
