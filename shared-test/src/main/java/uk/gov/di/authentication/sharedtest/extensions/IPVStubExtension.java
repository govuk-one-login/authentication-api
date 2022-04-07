package uk.gov.di.authentication.sharedtest.extensions;

import uk.gov.di.authentication.sharedtest.httpstub.HttpStubExtension;

import static java.lang.String.format;

public class IPVStubExtension extends HttpStubExtension {

    public IPVStubExtension(int port) {
        super(port);
    }

    public IPVStubExtension() {
        super();
    }

    public void init() {
        register(
                "/token",
                200,
                "application/json",
                format(
                        "{"
                                + "  \"access_token\": \"740e5834-3a29-46b4-9a6f-16142fde533a\","
                                + "  \"token_type\": \"bearer\","
                                + "  \"expires_in\": \"3600\","
                                + "  \"uri\": \"http://localhost:%1$d\""
                                + "}",
                        getHttpPort()));

        register(
                "/user-identity",
                200,
                "application/json",
                "{"
                        + "  \"sub\": \"740e5834-3a29-46b4-9a6f-16142fde533a\","
                        + "  \"vot\": \"P2\","
                        + "  \"vtm\": \"http://localhost/trustmark\","
                        + "  \"https://vocab.sign-in.service.gov.uk/v1/verifiableIdentityCredential\": \"some-encoded-credential\""
                        + "}");
    }
}
