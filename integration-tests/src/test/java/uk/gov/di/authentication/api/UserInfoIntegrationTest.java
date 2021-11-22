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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.lambda.UserInfoHandler;
import uk.gov.di.authentication.shared.entity.AccessTokenStore;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.helper.DynamoHelper;
import uk.gov.di.authentication.sharedtest.helper.KeyPairHelper;
import uk.gov.di.authentication.sharedtest.helper.KmsHelper;

import java.security.KeyPair;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static com.nimbusds.oauth2.sdk.token.BearerTokenError.INVALID_TOKEN;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class UserInfoIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String USERINFO_ENDPOINT = "/userinfo";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_PHONE_NUMBER = "01234567890";
    private static final String FORMATTED_PHONE_NUMBER = "+441234567890";
    private static final String TEST_PASSWORD = "password-1";
    private static final String CLIENT_ID = "client-id-one";
    private static final String ACCESS_TOKEN_PREFIX = "ACCESS_TOKEN:";

    @BeforeEach
    void setup() {
        handler = new UserInfoHandler(configurationService);
    }

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
        AccessTokenStore accessTokenStore =
                new AccessTokenStore(accessToken.getValue(), internalSubject.getValue());
        String accessTokenStoreString = new ObjectMapper().writeValueAsString(accessTokenStore);
        redis.addToRedis(
                ACCESS_TOKEN_PREFIX + CLIENT_ID + "." + publicSubject,
                accessTokenStoreString,
                300L);
        setUpDynamo(internalSubject);

        var response =
                makeRequest(
                        Optional.empty(),
                        Map.of("Authorization", accessToken.toAuthorizationHeader()),
                        Map.of());

        assertThat(response, hasStatus(200));
        UserInfo expectedUserInfoResponse = new UserInfo(publicSubject);
        expectedUserInfoResponse.setEmailAddress(TEST_EMAIL_ADDRESS);
        expectedUserInfoResponse.setEmailVerified(true);
        expectedUserInfoResponse.setPhoneNumber(FORMATTED_PHONE_NUMBER);
        expectedUserInfoResponse.setPhoneNumberVerified(true);
        assertThat(response.getBody(), equalTo(expectedUserInfoResponse.toJSONString()));
    }

    @Test
    public void shouldReturnInvalidTokenErrorWhenAccessTokenIsInvalid() {
        var response = makeRequest(Optional.empty(), Map.of("Authorization", "ru"), Map.of());

        assertThat(response, hasStatus(401));

        assertThat(
                response.getMultiValueHeaders().get("WWW-Authenticate"),
                equalTo(
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
                "public");
    }
}
