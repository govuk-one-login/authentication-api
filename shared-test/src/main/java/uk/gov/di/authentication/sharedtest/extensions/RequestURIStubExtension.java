package uk.gov.di.authentication.sharedtest.extensions;

import com.nimbusds.jwt.SignedJWT;
import uk.gov.di.authentication.sharedtest.httpstub.HttpStubExtension;

public class RequestURIStubExtension extends HttpStubExtension {

    public RequestURIStubExtension(int port) {
        super(port);
    }

    public RequestURIStubExtension() {
        super();
    }

    public void init(SignedJWT signedJWT) {
        register("/stub-request-uri", 200, "application/json", signedJWT.serialize());
    }
}
