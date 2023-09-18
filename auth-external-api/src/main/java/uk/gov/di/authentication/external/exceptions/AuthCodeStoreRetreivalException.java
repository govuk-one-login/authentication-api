package uk.gov.di.authentication.external.exceptions;

import com.nimbusds.oauth2.sdk.ErrorObject;

public class AuthCodeStoreRetreivalException extends Exception {
    final ErrorObject oAuth2Error;

    public AuthCodeStoreRetreivalException(String message, ErrorObject oAuth2Error) {
        super(message);
        this.oAuth2Error = oAuth2Error;
    }

    public ErrorObject getOAuth2Error() {
        return oAuth2Error;
    }
}
