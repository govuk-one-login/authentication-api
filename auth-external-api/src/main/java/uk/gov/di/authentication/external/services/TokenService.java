package uk.gov.di.authentication.external.services;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;

public class TokenService {
    public AccessTokenResponse generateNewBearerTokenAndTokenResponse() {
        BearerAccessToken token = new BearerAccessToken();
        var tokens = new Tokens(token, null);
        return new AccessTokenResponse(tokens);
    }

    public HTTPResponse generateTokenErrorResponse(ErrorObject errorObject) {
        TokenErrorResponse errorResponse = new TokenErrorResponse(errorObject);
        return errorResponse.toHTTPResponse();
    }
}
