package uk.gov.di.authentication.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
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
import uk.gov.di.authentication.helpers.KeyPairHelper;
import uk.gov.di.authentication.helpers.KmsHelper;
import uk.gov.di.authentication.helpers.RedisHelper;
import uk.gov.di.authentication.shared.entity.AuthenticationValues;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.TokenStore;

import java.security.KeyPair;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static com.nimbusds.oauth2.sdk.token.BearerTokenError.INVALID_TOKEN;
import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class UserInfoIntegrationTest extends IntegrationTestEndpoints {

    private static final String USERINFO_ENDPOINT = "/userinfo";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_PHONE_NUMBER = "01234567890";
    private static final String TEST_PASSWORD = "password-1";
    private static final String CLIENT_ID = "client-id-one";
    private static final String ACCESS_TOKEN_PREFIX = "ACCESS_TOKEN:";

    @Test
    public void shouldCallUserInfoWithAccessTokenAndReturn200() throws JsonProcessingException {
        Subject internalSubject = new Subject();
        Subject publicSubject = new Subject();
        LocalDateTime localDateTime = LocalDateTime.now().plusMinutes(10);
        Date expiryDate = Date.from(localDateTime.atZone(ZoneId.of("UTC")).toInstant());
        List<String> scopes = new ArrayList<>();
        scopes.add("email");
        scopes.add("phone");
        scopes.add("openid");
        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .claim("scope", scopes)
                        .issuer("issuer-id")
                        .expirationTime(expiryDate)
                        .issueTime(
                                Date.from(LocalDateTime.now().atZone(ZoneId.of("UTC")).toInstant()))
                        .claim("client_id", "client-id-one")
                        .subject(publicSubject.getValue())
                        .jwtID(UUID.randomUUID().toString())
                        .build();
        SignedJWT signedJWT = KmsHelper.signAccessToken(claimsSet);
        AccessToken accessToken = new BearerAccessToken(signedJWT.serialize());
        TokenStore accessTokenStore =
                new TokenStore(accessToken.getValue(), internalSubject.getValue());
        String accessTokenStoreString = new ObjectMapper().writeValueAsString(accessTokenStore);
        RedisHelper.addToRedis(
                ACCESS_TOKEN_PREFIX + CLIENT_ID + "." + publicSubject,
                accessTokenStoreString,
                300L);
        setUpDynamo(internalSubject);
        Client client = ClientBuilder.newClient();
        Response response =
                client.target(ROOT_RESOURCE_URL + USERINFO_ENDPOINT)
                        .request()
                        .header("Authorization", accessToken.toAuthorizationHeader())
                        .get();

        //        Commented out due to same reason as LogoutIntegration test. It's an issue with KSM
        // running inside localstack which causes the Caused by:
        // java.security.NoSuchAlgorithmException: EC KeyFactory not available error.
        //                assertEquals(200, response.getStatus());
        UserInfo expectedUserInfoResponse = new UserInfo(publicSubject);
        expectedUserInfoResponse.setEmailAddress(TEST_EMAIL_ADDRESS);
        expectedUserInfoResponse.setEmailVerified(true);
        expectedUserInfoResponse.setPhoneNumber(TEST_PHONE_NUMBER);
        expectedUserInfoResponse.setPhoneNumberVerified(true);
        //        assertThat(
        //                response.readEntity(String.class),
        //                equalTo(expectedUserInfoResponse.toJSONString()));
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

    private void setUpDynamo(Subject internalSubject) {
        DynamoHelper.signUp(TEST_EMAIL_ADDRESS, TEST_PASSWORD, internalSubject);
        DynamoHelper.addPhoneNumber(TEST_EMAIL_ADDRESS, TEST_PHONE_NUMBER);
        DynamoHelper.setPhoneNumberVerified(TEST_EMAIL_ADDRESS, true);
        KeyPair keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
        DynamoHelper.registerClient(
                CLIENT_ID,
                "test-client",
                singletonList("redirect-url"),
                singletonList(TEST_EMAIL_ADDRESS),
                List.of("openid", "email", "phone"),
                Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                singletonList("http://localhost/post-redirect-logout"),
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public",
                AuthenticationValues.MEDIUM_LEVEL.getValue());
    }
}
