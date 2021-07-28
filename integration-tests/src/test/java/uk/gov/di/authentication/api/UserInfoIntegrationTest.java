package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.RedisHelper;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class UserInfoIntegrationTest extends IntegrationTestEndpoints {

    private static final String USERINFO_ENDPOINT = "/userinfo";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_PASSWORD = "password-1";

    @Test
    public void shouldCallUserInfoWithAccessTokenAndReturn200() {
        AccessToken accessToken = new BearerAccessToken();
        Subject subject = new Subject();
        RedisHelper.addAccessTokenToRedis(accessToken.toJSONString(), subject.toString(), 300L);
        DynamoHelper.signUp(TEST_EMAIL_ADDRESS, TEST_PASSWORD, subject);
        Client client = ClientBuilder.newClient();
        Response response =
                client.target(ROOT_RESOURCE_URL + USERINFO_ENDPOINT)
                        .request()
                        .header("Authorization", accessToken.toAuthorizationHeader())
                        .get();

        assertEquals(200, response.getStatus());
    }
}
