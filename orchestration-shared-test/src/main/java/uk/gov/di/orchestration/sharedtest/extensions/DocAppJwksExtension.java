package uk.gov.di.orchestration.sharedtest.extensions;

import com.nimbusds.jose.jwk.JWKSet;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import uk.gov.di.orchestration.sharedtest.httpstub.HttpStubExtension;

public class DocAppJwksExtension extends HttpStubExtension implements BeforeAllCallback {

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

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        this.startStub();
    }
}
