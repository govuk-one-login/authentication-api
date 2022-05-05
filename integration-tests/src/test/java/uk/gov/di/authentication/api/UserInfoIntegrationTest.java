package uk.gov.di.authentication.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.lambda.UserInfoHandler;
import uk.gov.di.authentication.shared.entity.AccessTokenStore;
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.ValidClaims;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.helper.KeyPairHelper;
import uk.gov.di.authentication.sharedtest.helper.SignedCredentialHelper;

import java.security.KeyPair;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

import static com.nimbusds.oauth2.sdk.token.BearerTokenError.INVALID_TOKEN;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertNoAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class UserInfoIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_PHONE_NUMBER = "01234567890";
    private static final String FORMATTED_PHONE_NUMBER = "+441234567890";
    private static final String TEST_PASSWORD = "password-1";
    private static final String CLIENT_ID = "client-id-one";
    private static final String APP_CLIENT_ID = "app-client-id-one";
    private static final String ACCESS_TOKEN_PREFIX = "ACCESS_TOKEN:";
    private static final Subject PUBLIC_SUBJECT = new Subject();
    private static final Subject INTERNAL_SUBJECT = new Subject();
    private static final Scope DOC_APP_SCOPES =
            new Scope(OIDCScopeValue.OPENID, CustomScopeValue.DOC_CHECKING_APP);
    private static final Subject DOC_APP_PUBLIC_SUBJECT = new Subject();
    private static final String DOC_APP_CREDENTIAL = "doc-app-credential-11223344";

    private static final List<String> SCOPES =
            List.of(
                    OIDCScopeValue.OPENID.getValue(),
                    OIDCScopeValue.EMAIL.getValue(),
                    OIDCScopeValue.PHONE.getValue());
    private static final Date EXPIRY_DATE = NowHelper.nowPlus(10, ChronoUnit.MINUTES);

    @BeforeEach
    void setup() {
        handler = new UserInfoHandler(TEST_CONFIGURATION_SERVICE);
    }

    @Test
    void shouldCallUserInfoWithAccessTokenAndReturn200()
            throws JsonProcessingException, ParseException {
        var claimsSet =
                new JWTClaimsSet.Builder()
                        .claim("scope", SCOPES)
                        .issuer("issuer-id")
                        .expirationTime(EXPIRY_DATE)
                        .issueTime(NowHelper.now())
                        .claim("client_id", "client-id-one")
                        .subject(PUBLIC_SUBJECT.getValue())
                        .jwtID(UUID.randomUUID().toString())
                        .build();
        var signedJWT = tokenSigner.signJwt(claimsSet);
        var accessToken = new BearerAccessToken(signedJWT.serialize());
        var accessTokenStore =
                new AccessTokenStore(accessToken.getValue(), INTERNAL_SUBJECT.getValue());
        var accessTokenStoreString = objectMapper.writeValueAsString(accessTokenStore);
        redis.addToRedis(
                ACCESS_TOKEN_PREFIX + CLIENT_ID + "." + PUBLIC_SUBJECT,
                accessTokenStoreString,
                300L);
        setUpDynamo(null);

        var response =
                makeRequest(
                        Optional.empty(),
                        Map.of("Authorization", accessToken.toAuthorizationHeader()),
                        Map.of());

        assertThat(response, hasStatus(200));

        var userInfoResponse = UserInfo.parse(response.getBody());
        assertThat(userInfoResponse.getEmailVerified(), equalTo(true));
        assertThat(userInfoResponse.getEmailAddress(), equalTo(TEST_EMAIL_ADDRESS));
        assertThat(userInfoResponse.getPhoneNumber(), equalTo(FORMATTED_PHONE_NUMBER));
        assertThat(userInfoResponse.getPhoneNumberVerified(), equalTo(true));
        assertThat(userInfoResponse.getSubject(), equalTo(PUBLIC_SUBJECT));
        assertThat(userInfoResponse.toJWTClaimsSet().getClaims().size(), equalTo(5));

        assertNoAuditEventsReceived(auditTopic);
    }

    @Test
    void shouldReturnInvalidTokenErrorWhenAccessTokenIsInvalid() {
        var response = makeRequest(Optional.empty(), Map.of("Authorization", "ru"), Map.of());

        assertThat(response, hasStatus(401));

        assertThat(
                response.getMultiValueHeaders().get("WWW-Authenticate"),
                equalTo(
                        new UserInfoErrorResponse(INVALID_TOKEN)
                                .toHTTPResponse()
                                .getHeaderMap()
                                .get("WWW-Authenticate")));

        assertNoAuditEventsReceived(auditTopic);
    }

    @Test
    void shouldReturn200WhenIdentityIsEnabledAndIdentityClaimsArePresent()
            throws JsonProcessingException, ParseException {
        var configurationService = new UserInfoIntegrationTest.UserInfoConfigurationService();
        handler = new UserInfoHandler(configurationService);
        var claimsSetRequest =
                new ClaimsSetRequest()
                        .add(ValidClaims.CORE_IDENTITY_JWT.getValue())
                        .add(ValidClaims.ADDRESS.getValue())
                        .add(ValidClaims.PASSPORT.getValue());
        var oidcValidClaimsRequest =
                new OIDCClaimsRequest().withUserInfoClaimsRequest(claimsSetRequest);
        var claimsSet =
                new JWTClaimsSet.Builder()
                        .claim("scope", SCOPES)
                        .issuer("issuer-id")
                        .expirationTime(EXPIRY_DATE)
                        .issueTime(NowHelper.now())
                        .claim("client_id", "client-id-one")
                        .subject(PUBLIC_SUBJECT.getValue())
                        .jwtID(UUID.randomUUID().toString())
                        .claim(
                                "claims",
                                oidcValidClaimsRequest
                                        .getUserInfoClaimsRequest()
                                        .getEntries()
                                        .stream()
                                        .map(ClaimsSetRequest.Entry::getClaimName)
                                        .collect(Collectors.toList()))
                        .build();
        var signedJWT = tokenSigner.signJwt(claimsSet);
        var accessToken = new BearerAccessToken(signedJWT.serialize());
        var accessTokenStore =
                new AccessTokenStore(accessToken.getValue(), INTERNAL_SUBJECT.getValue());
        redis.addToRedis(
                ACCESS_TOKEN_PREFIX + CLIENT_ID + "." + PUBLIC_SUBJECT,
                objectMapper.writeValueAsString(accessTokenStore),
                300L);
        var signedCredential = SignedCredentialHelper.generateCredential();
        setUpDynamo(signedCredential.serialize());

        var response =
                makeRequest(
                        Optional.empty(),
                        Map.of("Authorization", accessToken.toAuthorizationHeader()),
                        Map.of());

        assertThat(response, hasStatus(200));
        var userInfoResponse = UserInfo.parse(response.getBody());
        assertThat(userInfoResponse.getEmailVerified(), equalTo(true));
        assertThat(userInfoResponse.getEmailAddress(), equalTo(TEST_EMAIL_ADDRESS));
        assertThat(userInfoResponse.getPhoneNumber(), equalTo(FORMATTED_PHONE_NUMBER));
        assertThat(userInfoResponse.getPhoneNumberVerified(), equalTo(true));
        assertThat(userInfoResponse.getSubject(), equalTo(PUBLIC_SUBJECT));
        assertThat(
                userInfoResponse.getClaim(ValidClaims.CORE_IDENTITY_JWT.getValue()),
                equalTo(signedCredential.serialize()));
        assertThat(userInfoResponse.toJWTClaimsSet().getClaims().size(), equalTo(6));

        assertNoAuditEventsReceived(auditTopic);
    }

    @Test
    void shouldCallUserInfoWithAccessTokenAndReturn200ForDocAppUser()
            throws JsonProcessingException, ParseException {

        documentAppCredentialStore.addCredential(
                DOC_APP_PUBLIC_SUBJECT.getValue(), DOC_APP_CREDENTIAL);

        var claimsSet =
                new JWTClaimsSet.Builder()
                        .claim("scope", DOC_APP_SCOPES.toStringList())
                        .issuer("issuer-id")
                        .expirationTime(EXPIRY_DATE)
                        .issueTime(NowHelper.now())
                        .claim("client_id", "app-client-id-one")
                        .subject(DOC_APP_PUBLIC_SUBJECT.getValue())
                        .jwtID(UUID.randomUUID().toString())
                        .build();
        var signedJWT = tokenSigner.signJwt(claimsSet);
        var accessToken = new BearerAccessToken(signedJWT.serialize());
        var accessTokenStore =
                new AccessTokenStore(accessToken.getValue(), INTERNAL_SUBJECT.getValue());
        var accessTokenStoreString = objectMapper.writeValueAsString(accessTokenStore);
        redis.addToRedis(
                ACCESS_TOKEN_PREFIX + APP_CLIENT_ID + "." + DOC_APP_PUBLIC_SUBJECT,
                accessTokenStoreString,
                300L);
        setUpDynamo(null);

        var response =
                makeRequest(
                        Optional.empty(),
                        Map.of("Authorization", accessToken.toAuthorizationHeader()),
                        Map.of());

        assertThat(response, hasStatus(200));

        var userInfoResponse = UserInfo.parse(response.getBody());
        assertThat(userInfoResponse.getClaim("doc-app-credential"), equalTo(DOC_APP_CREDENTIAL));
        assertThat(userInfoResponse.getSubject(), equalTo(DOC_APP_PUBLIC_SUBJECT));
        assertThat(userInfoResponse.toJWTClaimsSet().getClaims().size(), equalTo(2));

        assertNoAuditEventsReceived(auditTopic);
    }

    private void setUpDynamo(String coreIdentityJWT) {
        if (Objects.nonNull(coreIdentityJWT)) {
            identityStore.addCoreIdentityJWT(PUBLIC_SUBJECT.getValue(), coreIdentityJWT);
        }
        userStore.signUp(TEST_EMAIL_ADDRESS, TEST_PASSWORD, INTERNAL_SUBJECT);
        userStore.addPhoneNumber(TEST_EMAIL_ADDRESS, TEST_PHONE_NUMBER);
        userStore.setPhoneNumberVerified(TEST_EMAIL_ADDRESS, true);
        KeyPair keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
        clientStore.registerClient(
                CLIENT_ID,
                "test-client",
                singletonList("redirect-url"),
                singletonList(TEST_EMAIL_ADDRESS),
                List.of("openid", "email", "phone"),
                Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public",
                true);
        clientStore.registerClient(
                APP_CLIENT_ID,
                "app-test-client",
                singletonList("redirect-url"),
                singletonList(TEST_EMAIL_ADDRESS),
                List.of("openid", "doc-checking-app"),
                Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public",
                false,
                ClientType.APP);
    }

    private class UserInfoConfigurationService extends IntegrationTestConfigurationService {

        public UserInfoConfigurationService() {
            super(
                    auditTopic,
                    notificationsQueue,
                    auditSigningKey,
                    tokenSigner,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner);
        }

        @Override
        public boolean isIdentityEnabled() {
            return true;
        }
    }
}
