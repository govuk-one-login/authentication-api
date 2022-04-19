package uk.gov.di.authentication.oidc.entity;

import com.nimbusds.oauth2.sdk.ErrorObject;

import java.net.URI;

public class AuthRequestError {

    private ErrorObject errorObject;

    private URI redirectURI;

    public AuthRequestError(ErrorObject errorObject, URI redirectURI) {
        this.errorObject = errorObject;
        this.redirectURI = redirectURI;
    }

    public ErrorObject getErrorObject() {
        return errorObject;
    }

    public URI getRedirectURI() {
        return redirectURI;
    }
}
