package uk.gov.di.authentication.oidc.entity;

import com.nimbusds.oauth2.sdk.ErrorObject;

public class RequestObjectError {

    private ErrorObject errorObject;

    private String redirectURI;

    public RequestObjectError(ErrorObject errorObject, String redirectURI) {
        this.errorObject = errorObject;
        this.redirectURI = redirectURI;
    }

    public ErrorObject getErrorObject() {
        return errorObject;
    }

    public String getRedirectURI() {
        return redirectURI;
    }
}
