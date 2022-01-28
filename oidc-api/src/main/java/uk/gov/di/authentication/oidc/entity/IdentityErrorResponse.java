package uk.gov.di.authentication.oidc.entity;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ErrorResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.TokenSchemeError;

public class IdentityErrorResponse implements ErrorResponse {

    private final ErrorObject error;

    public IdentityErrorResponse(final ErrorObject error) {
        if (error == null) throw new IllegalArgumentException("The error must not be null");

        this.error = error;
    }

    @Override
    public ErrorObject getErrorObject() {
        return error;
    }

    @Override
    public boolean indicatesSuccess() {
        return false;
    }

    @Override
    public HTTPResponse toHTTPResponse() {
        HTTPResponse httpResponse;

        if (error != null && error.getHTTPStatusCode() > 0) {
            httpResponse = new HTTPResponse(error.getHTTPStatusCode());
        } else {
            httpResponse = new HTTPResponse(HTTPResponse.SC_BAD_REQUEST);
        }

        // Add the WWW-Authenticate header
        if (error instanceof TokenSchemeError) {
            httpResponse.setWWWAuthenticate(((TokenSchemeError) error).toWWWAuthenticateHeader());
        } else if (error != null) {
            httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
            httpResponse.setContent(error.toJSONObject().toJSONString());
        }

        return httpResponse;
    }
}
