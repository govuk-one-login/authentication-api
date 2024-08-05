package uk.gov.di.authentication.oidc.exceptions;

import com.nimbusds.oauth2.sdk.ErrorObject;

public class IncorrectRedirectUriException extends Exception {

    public IncorrectRedirectUriException(ErrorObject error) {
        super(error.getDescription());
    }
}
