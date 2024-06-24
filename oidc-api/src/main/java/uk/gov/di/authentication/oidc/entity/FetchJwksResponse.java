package uk.gov.di.authentication.oidc.entity;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.oauth2.sdk.ErrorObject;

public class FetchJwksResponse {

    private JWK jwk = null;
    private ErrorObject error = null;

    public FetchJwksResponse() {}

    public FetchJwksResponse(JWK jwk, ErrorObject error) {
        this.jwk = jwk;
        this.error = error;
    }

    public JWK getJwk() {
        return jwk;
    }

    public void setJwk(JWK jwk) {
        this.jwk = jwk;
    }

    public ErrorObject getError() {
        return error;
    }

    public void setError(ErrorObject error) {
        this.error = error;
    }
}
