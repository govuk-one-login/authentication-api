package uk.gov.di.orchestration.sharedtest.extensions;

import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import uk.gov.di.orchestration.shared.entity.MFAMethodType;
import uk.gov.di.orchestration.sharedtest.httpstub.HttpStubExtension;

import static java.lang.String.format;
import static uk.gov.di.authentication.oidc.entity.AuthUserInfoClaims.NEW_ACCOUNT;

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

        UserInfo userInfo = new UserInfo(subjectId);
        userInfo.setClaim(NEW_ACCOUNT.getValue(), true);
        userInfo.setClaim("verified_mfa_method_type", MFAMethodType.AUTH_APP.getValue());
        register("/userinfo", 200, "application/json", userInfo.toJSONString());
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

        UserInfo userInfo = new UserInfo(subjectId);
        userInfo.setClaim("new_account", true);
        userInfo.setClaim("verified_mfa_method_type", MFAMethodType.AUTH_APP.getValue());
        userInfo.setClaim("password_reset_time", passwordResetTime);
        register("/userinfo", 200, "application/json", userInfo.toJSONString());
    }
}
