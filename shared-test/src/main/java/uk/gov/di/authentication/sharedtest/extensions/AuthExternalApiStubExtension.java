package uk.gov.di.authentication.sharedtest.extensions;

import com.nimbusds.oauth2.sdk.id.Subject;
import uk.gov.di.authentication.sharedtest.httpstub.HttpStubExtension;

import static java.lang.String.format;

public class AuthExternalApiStubExtension extends HttpStubExtension {

    public AuthExternalApiStubExtension(int port) {
        super(port);
    }

    public AuthExternalApiStubExtension() {
        super();
    }

    public void init(Subject subjectId) {
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

        String userInfoContent =
                String.format(
                        "{" + "\"sub\": \"%s\"," + "\"new_account\": \"true\"" + "}",
                        subjectId.getValue());

        register("/userinfo", 200, "application/json", userInfoContent);
    }
}
