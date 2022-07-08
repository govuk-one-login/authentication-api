package uk.gov.di.authentication.sharedtest.extensions;

import com.nimbusds.jose.jwk.JWKSet;
import uk.gov.di.authentication.sharedtest.httpstub.HttpStubExtension;

public class DocAppJwksExtension extends HttpStubExtension {

    public DocAppJwksExtension(int port) {
        super(port);
    }

    public DocAppJwksExtension() {
        super();
    }

    public void init(JWKSet jwkSet) {
        register(
                "/.well-known/jwks.json",
                200,
                "application/json",
                jwkSet.toPublicJWKSet().toString());
    }
}
