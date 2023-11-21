package uk.gov.di.authentication.sharedtest.extensions;

import uk.gov.di.authentication.sharedtest.httpstub.HttpStubExtension;

public class AccountInterventionsStubExtension extends HttpStubExtension {

    public AccountInterventionsStubExtension(int port) {
        super(port);
    }

    public AccountInterventionsStubExtension() {
        super();
    }

    public void init(String userId) {
        register(
                "/v1/ais/" + userId,
                200,
                "application/json",
                "{"
                        + "  \"intervention\": {"
                        + "    \"updatedAt\": 1696969322935,"
                        + "    \"appliedAt\": 1696869005821,"
                        + "    \"sentAt\": 1696869003456,"
                        + "    \"description\": \"AIS_USER_PASSWORD_RESET_AND_IDENTITY_VERIFIED\","
                        + "    \"reprovedIdentityAt\": 1696969322935,"
                        + "    \"resetPasswordAt\": 1696875903456"
                        + "  },"
                        + "  \"state\": {"
                        + "    \"blocked\": false,"
                        + "    \"suspended\": false,"
                        + "    \"reproveIdentity\": false,"
                        + "    \"resetPassword\": false"
                        + "  }"
                        + "}");
    }
}
