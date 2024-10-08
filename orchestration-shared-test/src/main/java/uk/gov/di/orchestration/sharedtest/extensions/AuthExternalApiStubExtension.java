package uk.gov.di.orchestration.sharedtest.extensions;

import com.nimbusds.oauth2.sdk.id.Subject;
import uk.gov.di.orchestration.sharedtest.httpstub.HttpStubExtension;

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
                        "{"
                                + "\"sub\": \"%s\","
                                + "\"new_account\": true,"
                                + "\"verified_mfa_method_type\": \"AUTH_APP\""
                                + "}",
                        subjectId.getValue());

        register("/userinfo", 200, "application/json", userInfoContent);
    }

    public void init(Subject subjectId, Long passwordResetTime) {
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
                        "{"
                                + "\"sub\": \"%s\","
                                + "\"new_account\": true,"
                                + "\"verified_mfa_method_type\": \"AUTH_APP\","
                                + "\"password_reset_time\": %s"
                                + "}",
                        subjectId.getValue(), passwordResetTime.toString());

        register("/userinfo", 200, "application/json", userInfoContent);
    }
}
