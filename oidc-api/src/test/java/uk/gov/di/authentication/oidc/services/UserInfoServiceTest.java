package uk.gov.di.authentication.oidc.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.entity.AccessTokenStore;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.exceptions.UserInfoValidationException;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.TokenValidationService;
import uk.gov.di.authentication.sharedtest.helper.TokenGeneratorHelper;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class UserInfoServiceTest {

    private UserInfoService userInfoService;
    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final TokenValidationService tokenValidationService =
            mock(TokenValidationService.class);
    private final DynamoClientService clientService = mock(DynamoClientService.class);
    private static final Subject INTERNAL_SUBJECT = new Subject("internal-subject");
    private static final Subject SUBJECT = new Subject("some-subject");
    private static final List<String> SCOPES =
            List.of(
                    OIDCScopeValue.OPENID.getValue(),
                    OIDCScopeValue.EMAIL.getValue(),
                    OIDCScopeValue.PHONE.getValue());
    private static final String CLIENT_ID = "client-id";
    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String PHONE_NUMBER = "01234567891";
    private static final String BASE_URL = "http://example.com";
    private static final String KEY_ID = "14342354354353";
    private static final String ACCESS_TOKEN_PREFIX = "ACCESS_TOKEN:";
    private AccessToken accessToken;

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(UserInfoService.class);

    @AfterEach
    public void tearDown() {
        assertThat(
                logging.events(),
                not(hasItem(withMessageContaining(CLIENT_ID, SUBJECT.toString()))));
    }

    @BeforeEach
    public void setUp() throws JOSEException {
        userInfoService =
                new UserInfoService(
                        redisConnectionService,
                        authenticationService,
                        tokenValidationService,
                        clientService);
        accessToken = createSignedAccessToken();
    }

    @Test
    public void shouldSuccessfullyProcessUserInfoRequest()
            throws JsonProcessingException, UserInfoValidationException {
        when(tokenValidationService.validateAccessTokenSignature(accessToken)).thenReturn(true);
        when(clientService.getClient(CLIENT_ID))
                .thenReturn(Optional.of(generateClientRegistry(SCOPES)));
        when(redisConnectionService.getValue(ACCESS_TOKEN_PREFIX + CLIENT_ID + "." + SUBJECT))
                .thenReturn(
                        new ObjectMapper()
                                .writeValueAsString(
                                        new AccessTokenStore(
                                                accessToken.getValue(),
                                                INTERNAL_SUBJECT.getValue())));
        when(authenticationService.getUserProfileFromSubject(INTERNAL_SUBJECT.getValue()))
                .thenReturn(generateUserprofile());

        UserInfo userInfo =
                userInfoService.processUserInfoRequest(accessToken.toAuthorizationHeader());
        assertEquals(userInfo.getEmailAddress(), EMAIL);
        assertEquals(userInfo.getEmailVerified(), true);
        assertEquals(userInfo.getPhoneNumber(), PHONE_NUMBER);
        assertEquals(userInfo.getPhoneNumberVerified(), true);
        verify(redisConnectionService, times(1))
                .deleteValue(ACCESS_TOKEN_PREFIX + CLIENT_ID + "." + SUBJECT);
    }

    @Test
    public void shouldThrowExceptionWhenTokenSignatureIsInvalid() {
        when(tokenValidationService.validateAccessTokenSignature(accessToken)).thenReturn(false);

        UserInfoValidationException userInfoValidationException =
                assertThrows(
                        UserInfoValidationException.class,
                        () ->
                                userInfoService.processUserInfoRequest(
                                        accessToken.toAuthorizationHeader()),
                        "Expected to throw UserInfoValidationException");

        assertEquals(
                userInfoValidationException.getMessage(),
                "Unable to validate AccessToken signature");
        assertEquals(userInfoValidationException.getError(), BearerTokenError.INVALID_TOKEN);
    }

    @Test
    public void shouldThrowExceptionWhenTokenHasExpired() throws JOSEException {
        accessToken = createSignedExpiredAccessToken();
        UserInfoValidationException userInfoValidationException =
                assertThrows(
                        UserInfoValidationException.class,
                        () ->
                                userInfoService.processUserInfoRequest(
                                        accessToken.toAuthorizationHeader()),
                        "Expected to throw UserInfoValidationException");

        assertEquals(userInfoValidationException.getMessage(), "Invalid Access Token");
        assertEquals(userInfoValidationException.getError(), BearerTokenError.INVALID_TOKEN);
    }

    @Test
    public void shouldThrowExceptionWhenClientIsNotFoundInClientRegistry() {
        when(tokenValidationService.validateAccessTokenSignature(accessToken)).thenReturn(true);
        when(clientService.getClient(CLIENT_ID)).thenReturn(Optional.empty());

        UserInfoValidationException userInfoValidationException =
                assertThrows(
                        UserInfoValidationException.class,
                        () ->
                                userInfoService.processUserInfoRequest(
                                        accessToken.toAuthorizationHeader()),
                        "Expected to throw UserInfoValidationException");

        assertEquals(userInfoValidationException.getMessage(), "Client not found");
        assertEquals(userInfoValidationException.getError(), BearerTokenError.INVALID_TOKEN);
    }

    @Test
    public void shouldThrowExceptionWhenScopesAreInvalid() {
        List<String> scopes =
                List.of(OIDCScopeValue.OPENID.getValue(), OIDCScopeValue.ADDRESS.getValue());
        when(tokenValidationService.validateAccessTokenSignature(accessToken)).thenReturn(true);
        when(clientService.getClient(CLIENT_ID))
                .thenReturn(Optional.of(generateClientRegistry(scopes)));

        UserInfoValidationException userInfoValidationException =
                assertThrows(
                        UserInfoValidationException.class,
                        () ->
                                userInfoService.processUserInfoRequest(
                                        accessToken.toAuthorizationHeader()),
                        "Expected to throw UserInfoValidationException");

        assertEquals(userInfoValidationException.getMessage(), "Invalid Scopes");
        assertEquals(userInfoValidationException.getError(), OAuth2Error.INVALID_SCOPE);
    }

    @Test
    public void shouldThrowExceptionWhenAccessTokenNotFoundInRedis() {
        when(tokenValidationService.validateAccessTokenSignature(accessToken)).thenReturn(true);
        when(clientService.getClient(CLIENT_ID))
                .thenReturn(Optional.of(generateClientRegistry(SCOPES)));
        when(redisConnectionService.getValue(ACCESS_TOKEN_PREFIX + CLIENT_ID + "." + SUBJECT))
                .thenReturn(null);

        UserInfoValidationException userInfoValidationException =
                assertThrows(
                        UserInfoValidationException.class,
                        () ->
                                userInfoService.processUserInfoRequest(
                                        accessToken.toAuthorizationHeader()),
                        "Expected to throw UserInfoValidationException");

        assertEquals(userInfoValidationException.getMessage(), "Invalid Access Token");
        assertEquals(userInfoValidationException.getError(), BearerTokenError.INVALID_TOKEN);
    }

    @Test
    public void shouldThrowExceptionWhenAccessTokenSentIsNotTheSameAsInRedis()
            throws JsonProcessingException, JOSEException {
        when(tokenValidationService.validateAccessTokenSignature(accessToken)).thenReturn(true);
        when(clientService.getClient(CLIENT_ID))
                .thenReturn(Optional.of(generateClientRegistry(SCOPES)));
        when(redisConnectionService.getValue(ACCESS_TOKEN_PREFIX + CLIENT_ID + "." + SUBJECT))
                .thenReturn(
                        new ObjectMapper()
                                .writeValueAsString(
                                        new AccessTokenStore(
                                                createSignedAccessToken().getValue(),
                                                INTERNAL_SUBJECT.getValue())));

        UserInfoValidationException userInfoValidationException =
                assertThrows(
                        UserInfoValidationException.class,
                        () ->
                                userInfoService.processUserInfoRequest(
                                        accessToken.toAuthorizationHeader()),
                        "Expected to throw UserInfoValidationException");

        assertEquals(userInfoValidationException.getMessage(), "Invalid Access Token");
        assertEquals(userInfoValidationException.getError(), BearerTokenError.INVALID_TOKEN);
    }

    @Test
    public void shouldThrowExceptionWhenUnableToParseAccessToken() {
        UserInfoValidationException userInfoValidationException =
                assertThrows(
                        UserInfoValidationException.class,
                        () -> userInfoService.processUserInfoRequest("rubbish-access-token"),
                        "Expected to throw UserInfoValidationException");

        assertEquals(userInfoValidationException.getMessage(), "Unable to parse AccessToken");
        assertEquals(userInfoValidationException.getError(), BearerTokenError.INVALID_TOKEN);
    }

    private AccessToken createSignedAccessToken() throws JOSEException {
        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256)
                        .keyID(KEY_ID)
                        .algorithm(JWSAlgorithm.ES256)
                        .generate();
        ECDSASigner signer = new ECDSASigner(ecSigningKey);
        SignedJWT signedJWT =
                TokenGeneratorHelper.generateSignedToken(
                        CLIENT_ID, BASE_URL, SCOPES, signer, SUBJECT, ecSigningKey.getKeyID());
        return new BearerAccessToken(signedJWT.serialize());
    }

    private AccessToken createSignedExpiredAccessToken() throws JOSEException {
        LocalDateTime localDateTime = LocalDateTime.now().minusMinutes(2);
        Date expiryDate = Date.from(localDateTime.atZone(ZoneId.of("UTC")).toInstant());
        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256)
                        .keyID(KEY_ID)
                        .algorithm(JWSAlgorithm.ES256)
                        .generate();
        ECDSASigner signer = new ECDSASigner(ecSigningKey);
        SignedJWT signedJWT =
                TokenGeneratorHelper.generateSignedToken(
                        CLIENT_ID,
                        BASE_URL,
                        SCOPES,
                        signer,
                        SUBJECT,
                        ecSigningKey.getKeyID(),
                        expiryDate);
        return new BearerAccessToken(signedJWT.serialize());
    }

    private ClientRegistry generateClientRegistry(List<String> scopes) {
        return new ClientRegistry()
                .setRedirectUrls(singletonList("http://localhost/redirect"))
                .setClientID(CLIENT_ID)
                .setContacts(singletonList("joe.bloggs@digital.cabinet-office.gov.uk"))
                .setPublicKey(null)
                .setScopes(scopes);
    }

    private UserProfile generateUserprofile() {
        return new UserProfile()
                .setEmail("joe.bloggs@digital.cabinet-office.gov.uk")
                .setEmailVerified(true)
                .setPhoneNumber(PHONE_NUMBER)
                .setPhoneNumberVerified(true)
                .setSubjectID(SUBJECT.toString())
                .setCreated(LocalDateTime.now().toString())
                .setUpdated(LocalDateTime.now().toString());
    }
}
