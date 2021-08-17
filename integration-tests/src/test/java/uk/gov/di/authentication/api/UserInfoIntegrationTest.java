package uk.gov.di.authentication.api;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.helpers.DynamoHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.authentication.helpers.TokenGeneratorHelper;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static com.nimbusds.oauth2.sdk.token.BearerTokenError.INVALID_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class UserInfoIntegrationTest extends IntegrationTestEndpoints {

    private static final String USERINFO_ENDPOINT = "/userinfo";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_PHONE_NUMBER = "01234567890";
    private static final String TEST_PASSWORD = "password-1";

    @Test
    public void shouldCallUserInfoWithAccessTokenAndReturn200() throws JOSEException {
        RSAKey signingKey =
                new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
        List<String> scopes = new ArrayList<>();
        scopes.add("email");
        scopes.add("phone");
        scopes.add("oidc");
        SignedJWT signedAccessToken =
                TokenGeneratorHelper.generateAccessToken(
                        "client-id-one", "issuer-id", scopes, signingKey);
        AccessToken accessToken = new BearerAccessToken(signedAccessToken.serialize());
        Subject subject = new Subject();
        RedisHelper.addAccessTokenToRedis(accessToken.toJSONString(), subject.toString(), 300L);
        DynamoHelper.signUp(TEST_EMAIL_ADDRESS, TEST_PASSWORD, subject);
        DynamoHelper.addPhoneNumber(TEST_EMAIL_ADDRESS, TEST_PHONE_NUMBER);
        DynamoHelper.setPhoneNumberVerified(TEST_EMAIL_ADDRESS, true);
        Client client = ClientBuilder.newClient();
        Response response =
                client.target(ROOT_RESOURCE_URL + USERINFO_ENDPOINT)
                        .request()
                        .header("Authorization", accessToken.toAuthorizationHeader())
                        .get();

        assertEquals(200, response.getStatus());
        UserInfo expectedUserInfoResponse = new UserInfo(subject);
        expectedUserInfoResponse.setEmailAddress(TEST_EMAIL_ADDRESS);
        expectedUserInfoResponse.setEmailVerified(true);
        expectedUserInfoResponse.setPhoneNumber(TEST_PHONE_NUMBER);
        expectedUserInfoResponse.setPhoneNumberVerified(true);
        assertThat(
                response.readEntity(String.class),
                equalTo(expectedUserInfoResponse.toJSONString()));
    }

    @Test
    public void shouldReturnInvalidTokenErrorWhenAccessTokenIsInvalid() {
        Client client = ClientBuilder.newClient();
        Response response =
                client.target(ROOT_RESOURCE_URL + USERINFO_ENDPOINT)
                        .request()
                        .header("Authorization", "ru")
                        .get();
        assertEquals(401, response.getStatus());
        assertTrue(
                response.getHeaders()
                        .get("www-authenticate")
                        .equals(
                                new UserInfoErrorResponse(INVALID_TOKEN)
                                        .toHTTPResponse()
                                        .getHeaderMap()
                                        .get("WWW-Authenticate")));
    }
}
