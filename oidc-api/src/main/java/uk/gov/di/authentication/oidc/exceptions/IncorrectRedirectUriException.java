package uk.gov.di.authentication.oidc.exceptions;

import com.nimbusds.oauth2.sdk.ErrorObject;

import static java.lang.String.format;

public class IncorrectRedirectUriException extends Exception {

    public IncorrectRedirectUriException(ErrorObject error) {
        super(format(error.getDescription()));
    }
}
