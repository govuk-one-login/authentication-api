package uk.gov.di.orchestration.sharedtest.extensions;

import com.nimbusds.jose.jwk.JWKSet;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import uk.gov.di.orchestration.sharedtest.httpstub.HttpStubExtension;

import java.net.MalformedURLException;
import java.net.URL;

public class JwksExtension extends HttpStubExtension implements BeforeAllCallback {
    private String endpoint = "/.well-known/jwks.json";

    public JwksExtension(int port) {
        super(port);
    }

    public JwksExtension() {
        super();
    }

    public URL getJwksUrl() throws MalformedURLException {
        return uri(endpoint).toURL();
    }

    public void init(JWKSet jwkSet) {
        init("/.well-known/jwks.json", jwkSet);
    }

    public void init(String path, JWKSet jwkSet) {
        endpoint = path;
        register(path, 200, "application/json", jwkSet.toPublicJWKSet().toString());
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        this.startStub();
    }
}
