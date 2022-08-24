package uk.gov.di.authentication.api;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.exceptions.UserInfoException;
import uk.gov.di.authentication.oidc.lambda.UserInfoHandler;
import uk.gov.di.authentication.shared.entity.AccessTokenStore;
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.entity.LevelOfConfidence;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.ValidClaims;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.DocumentAppCredentialStoreExtension;
import uk.gov.di.authentication.sharedtest.extensions.IdentityStoreExtension;
import uk.gov.di.authentication.sharedtest.helper.KeyPairHelper;
import uk.gov.di.authentication.sharedtest.helper.SignedCredentialHelper;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.authentication.oidc.domain.OidcAuditableEvent.USER_INFO_RETURNED;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertEventTypesReceivedByBothServices;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertNoAuditEventsReceivedByEitherService;
import static uk.gov.di.authentication.sharedtest.helper.IdentityTestData.ADDRESS_CLAIM;
import static uk.gov.di.authentication.sharedtest.helper.IdentityTestData.CORE_IDENTITY_CLAIM;
import static uk.gov.di.authentication.sharedtest.helper.IdentityTestData.PASSPORT_CLAIM;
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
    private static String DOC_APP_CREDENTIAL;

    private static final List<String> SCOPES =
            List.of(
                    OIDCScopeValue.OPENID.getValue(),
                    OIDCScopeValue.EMAIL.getValue(),
                    OIDCScopeValue.PHONE.getValue());
    private static final Date EXPIRY_DATE = NowHelper.nowPlus(10, ChronoUnit.MINUTES);

    @BeforeEach
    void setup() throws JOSEException, NoSuchAlgorithmException {
        var configuration =
                new IntegrationTestConfigurationService(
                        auditTopic,
                        notificationsQueue,
                        auditSigningKey,
                        tokenSigner,
                        ipvPrivateKeyJwtSigner,
                        spotQueue,
                        docAppPrivateKeyJwtSigner,
                        configurationParameters) {

                    @Override
                    public boolean isTxmaAuditEnabled() {
                        return true;
                    }

                    @Override
                    public String getTxmaAuditQueueUrl() {
                        return txmaAuditQueue.getQueueUrl();
                    }
                };

        handler = new UserInfoHandler(configuration);
        var keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
        DOC_APP_CREDENTIAL =
                generateSignedJWT(new JWTClaimsSet.Builder().build(), keyPair).serialize();
    }

    @Test
    void shouldCallUserInfoWithAccessTokenAndReturn200() throws Json.JsonException, ParseException {
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
        setUpDynamo(null, null, 0, false);

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

        assertEventTypesReceivedByBothServices(
                auditTopic, txmaAuditQueue, singletonList(USER_INFO_RETURNED));
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

        assertNoAuditEventsReceivedByEitherService(auditTopic, txmaAuditQueue);
    }

    @Test
    void shouldReturn200WhenIdentityIsEnabledAndIdentityClaimsArePresent()
            throws Json.JsonException, ParseException {
        var signedCredential = SignedCredentialHelper.generateCredential();
        setUpDynamo(
                signedCredential.serialize(),
                Map.of(
                        ValidClaims.ADDRESS.getValue(),
                        ADDRESS_CLAIM,
                        ValidClaims.PASSPORT.getValue(),
                        PASSPORT_CLAIM),
                180,
                true);

        var response = makeIdentityUserinfoRequest();

        assertThat(response, hasStatus(200));
        var userInfoResponse = UserInfo.parse(response.getBody());
        assertThat(userInfoResponse.getEmailVerified(), equalTo(true));
        assertThat(userInfoResponse.getEmailAddress(), equalTo(TEST_EMAIL_ADDRESS));
        assertThat(userInfoResponse.getPhoneNumber(), equalTo(FORMATTED_PHONE_NUMBER));
        assertThat(userInfoResponse.getPhoneNumberVerified(), equalTo(true));
        assertThat(userInfoResponse.getSubject(), equalTo(PUBLIC_SUBJECT));
        var addressClaim = (JSONArray) userInfoResponse.getClaim(ValidClaims.ADDRESS.getValue());
        assertThat(((JSONObject) addressClaim.get(0)).size(), equalTo(7));
        var passportClaim = (JSONArray) userInfoResponse.getClaim(ValidClaims.PASSPORT.getValue());
        assertThat(((JSONObject) passportClaim.get(0)).size(), equalTo(2));
        assertThat(
                userInfoResponse.getClaim(ValidClaims.CORE_IDENTITY_JWT.getValue()),
                equalTo(signedCredential.serialize()));
        assertThat(userInfoResponse.toJWTClaimsSet().getClaims().size(), equalTo(8));

        assertEventTypesReceivedByBothServices(
                auditTopic, txmaAuditQueue, singletonList(USER_INFO_RETURNED));
    }

    @Test
    void shouldNotReturnIdentityCredentialsWhenTTLHasExpired()
            throws Json.JsonException, ParseException {
        setUpDynamo(
                SignedCredentialHelper.generateCredential().serialize(),
                Map.of(
                        ValidClaims.ADDRESS.getValue(),
                        ADDRESS_CLAIM,
                        ValidClaims.PASSPORT.getValue(),
                        PASSPORT_CLAIM),
                0,
                true);

        var response = makeIdentityUserinfoRequest();

        assertThat(response, hasStatus(200));
        var userInfoResponse = UserInfo.parse(response.getBody());
        assertThat(userInfoResponse.getEmailVerified(), equalTo(true));
        assertThat(userInfoResponse.getEmailAddress(), equalTo(TEST_EMAIL_ADDRESS));
        assertThat(userInfoResponse.getPhoneNumber(), equalTo(FORMATTED_PHONE_NUMBER));
        assertThat(userInfoResponse.getPhoneNumberVerified(), equalTo(true));
        assertThat(userInfoResponse.getSubject(), equalTo(PUBLIC_SUBJECT));
        assertNull(userInfoResponse.getClaim(ValidClaims.ADDRESS.getValue()));
        assertNull(userInfoResponse.getClaim(ValidClaims.PASSPORT.getValue()));
        assertNull(userInfoResponse.getClaim(ValidClaims.CORE_IDENTITY_JWT.getValue()));

        assertEventTypesReceivedByBothServices(
                auditTopic, txmaAuditQueue, singletonList(USER_INFO_RETURNED));
    }

    @Test
    void shouldNotReturnIdentityCredentialsWhenNoneArePresentInDB()
            throws Json.JsonException, ParseException {
        setUpDynamo(null, null, 0, true);

        var response = makeIdentityUserinfoRequest();

        assertThat(response, hasStatus(200));
        var userInfoResponse = UserInfo.parse(response.getBody());
        assertThat(userInfoResponse.getEmailVerified(), equalTo(true));
        assertThat(userInfoResponse.getEmailAddress(), equalTo(TEST_EMAIL_ADDRESS));
        assertThat(userInfoResponse.getPhoneNumber(), equalTo(FORMATTED_PHONE_NUMBER));
        assertThat(userInfoResponse.getPhoneNumberVerified(), equalTo(true));
        assertThat(userInfoResponse.getSubject(), equalTo(PUBLIC_SUBJECT));
        assertNull(userInfoResponse.getClaim(ValidClaims.ADDRESS.getValue()));
        assertNull(userInfoResponse.getClaim(ValidClaims.PASSPORT.getValue()));
        assertNull(userInfoResponse.getClaim(ValidClaims.CORE_IDENTITY_JWT.getValue()));

        assertEventTypesReceivedByBothServices(
                auditTopic, txmaAuditQueue, singletonList(USER_INFO_RETURNED));
    }

    @Test
    void shouldCallUserInfoWithAccessTokenAndReturn200ForDocAppUser()
            throws Json.JsonException, ParseException {
        var documentAppCredentialStore = new DocumentAppCredentialStoreExtension(180);
        documentAppCredentialStore.addCredential(
                DOC_APP_PUBLIC_SUBJECT.getValue(), List.of(DOC_APP_CREDENTIAL));
        setUpAppClientInDynamo();
        var response = makeDocAppUserinfoRequest();

        assertThat(response, hasStatus(200));

        var userInfoResponse = UserInfo.parse(response.getBody());
        assertThat(
                userInfoResponse.getClaim("doc-app-credential"),
                equalTo(List.of(DOC_APP_CREDENTIAL)));
        assertThat(userInfoResponse.getSubject(), equalTo(DOC_APP_PUBLIC_SUBJECT));
        assertThat(userInfoResponse.toJWTClaimsSet().getClaims().size(), equalTo(2));

        assertEventTypesReceivedByBothServices(
                auditTopic, txmaAuditQueue, singletonList(USER_INFO_RETURNED));
    }

    @Test
    void shouldNotReturnDocAppCredentialWhenTTLHasExpired() {
        var documentAppCredentialStore = new DocumentAppCredentialStoreExtension(0);
        documentAppCredentialStore.addCredential(
                DOC_APP_PUBLIC_SUBJECT.getValue(), List.of(DOC_APP_CREDENTIAL));
        setUpAppClientInDynamo();

        assertThrows(
                UserInfoException.class,
                this::makeDocAppUserinfoRequest,
                "Expected to throw exception");

        assertNoAuditEventsReceivedByEitherService(auditTopic, txmaAuditQueue);
    }

    @Test
    void shouldThrowWhenNoDocAppCredentialIsPresentInDB() {
        setUpAppClientInDynamo();

        assertThrows(
                UserInfoException.class,
                this::makeDocAppUserinfoRequest,
                "Expected to throw exception");

        assertNoAuditEventsReceivedByEitherService(auditTopic, txmaAuditQueue);
    }

    public static SignedJWT generateSignedJWT(JWTClaimsSet jwtClaimsSet, KeyPair keyPair)
            throws JOSEException {
        var jwsHeader = new JWSHeader(JWSAlgorithm.ES256);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        var ecdsaSigner = new ECDSASigner((ECPrivateKey) keyPair.getPrivate());
        signedJWT.sign(ecdsaSigner);
        return signedJWT;
    }

    private APIGatewayProxyResponseEvent makeIdentityUserinfoRequest() throws Json.JsonException {
        var configurationService = new UserInfoConfigurationService();
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

        return makeRequest(
                Optional.empty(),
                Map.of("Authorization", accessToken.toAuthorizationHeader()),
                Map.of());
    }

    private APIGatewayProxyResponseEvent makeDocAppUserinfoRequest() throws Json.JsonException {
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
        return makeRequest(
                Optional.empty(),
                Map.of("Authorization", accessToken.toAuthorizationHeader()),
                Map.of());
    }

    private void setUpDynamo(
            String coreIdentityJWT,
            Map<String, String> additionalClaims,
            long ttl,
            boolean identitySupported) {
        IdentityStoreExtension identityStore = new IdentityStoreExtension(ttl);
        if (Objects.nonNull(additionalClaims)) {
            identityStore.saveIdentityClaims(
                    PUBLIC_SUBJECT.getValue(),
                    additionalClaims,
                    LevelOfConfidence.MEDIUM_LEVEL.getValue(),
                    CORE_IDENTITY_CLAIM);
        }
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
                true,
                ClientType.WEB,
                identitySupported);
    }

    private void setUpAppClientInDynamo() {
        KeyPair keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
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

    private static class UserInfoConfigurationService extends IntegrationTestConfigurationService {

        public UserInfoConfigurationService() {
            super(
                    auditTopic,
                    notificationsQueue,
                    auditSigningKey,
                    tokenSigner,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters);
        }

        @Override
        public boolean isIdentityEnabled() {
            return true;
        }

        @Override
        public boolean isTxmaAuditEnabled() {
            return true;
        }

        @Override
        public String getTxmaAuditQueueUrl() {
            return txmaAuditQueue.getQueueUrl();
        }
    }
}
