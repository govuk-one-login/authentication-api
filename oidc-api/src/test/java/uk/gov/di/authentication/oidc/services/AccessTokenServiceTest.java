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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.oidc.entity.AccessTokenInfo;
import uk.gov.di.authentication.shared.entity.AccessTokenStore;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.exceptions.AccessTokenException;
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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class AccessTokenServiceTest {

    private AccessTokenService validationService;
    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
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
    private static final String BASE_URL = "http://example.com";
    private static final String KEY_ID = "14342354354353";
    private static final String ACCESS_TOKEN_PREFIX = "ACCESS_TOKEN:";
    private AccessToken accessToken;

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(AccessTokenService.class);

    @AfterEach
    void tearDown() {
        assertThat(
                logging.events(),
                not(hasItem(withMessageContaining(CLIENT_ID, SUBJECT.toString()))));
    }

    @BeforeEach
    void setUp() throws JOSEException {
        validationService =
                new AccessTokenService(
                        redisConnectionService, clientService, tokenValidationService);
        accessToken = createSignedAccessToken();
    }

    @Test
    void shouldReturnAccessTokenInfoWhenAccessTokenIsValid()
            throws JsonProcessingException, AccessTokenException {
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

        AccessTokenInfo accessTokenInfo =
                validationService.parse(accessToken.toAuthorizationHeader());

        assertThat(
                accessTokenInfo.getAccessTokenStore().getToken(), equalTo(accessToken.getValue()));
        assertThat(
                accessTokenInfo.getAccessTokenStore().getInternalSubjectId(),
                equalTo(INTERNAL_SUBJECT.getValue()));
        assertThat(accessTokenInfo.getPublicSubject(), equalTo(SUBJECT.getValue()));
        assertThat(accessTokenInfo.getScopes(), equalTo(SCOPES));
    }

    @Test
    void shouldThrowExceptionWhenTokenSignatureIsInvalid() {
        when(tokenValidationService.validateAccessTokenSignature(accessToken)).thenReturn(false);

        AccessTokenException accessTokenException =
                assertThrows(
                        AccessTokenException.class,
                        () -> validationService.parse(accessToken.toAuthorizationHeader()),
                        "Expected to throw AccessTokenException");

        assertThat(
                accessTokenException.getMessage(),
                equalTo("Unable to validate AccessToken signature"));
        assertThat(accessTokenException.getError(), equalTo(BearerTokenError.INVALID_TOKEN));
    }

    @Test
    void shouldThrowExceptionWhenTokenHasExpired() throws JOSEException {
        accessToken = createSignedExpiredAccessToken();
        AccessTokenException accessTokenException =
                assertThrows(
                        AccessTokenException.class,
                        () -> validationService.parse(accessToken.toAuthorizationHeader()),
                        "Expected to throw AccessTokenException");

        assertThat(accessTokenException.getMessage(), equalTo("Invalid Access Token"));
        assertThat(accessTokenException.getError(), equalTo(BearerTokenError.INVALID_TOKEN));
    }

    @Test
    void shouldThrowExceptionWhenClientIsNotFoundInClientRegistry() {
        when(tokenValidationService.validateAccessTokenSignature(accessToken)).thenReturn(true);
        when(clientService.getClient(CLIENT_ID)).thenReturn(Optional.empty());

        AccessTokenException accessTokenException =
                assertThrows(
                        AccessTokenException.class,
                        () -> validationService.parse(accessToken.toAuthorizationHeader()),
                        "Expected to throw AccessTokenException");

        assertThat(accessTokenException.getMessage(), equalTo("Client not found"));
        assertThat(accessTokenException.getError(), equalTo(BearerTokenError.INVALID_TOKEN));
    }

    @Test
    void shouldThrowExceptionWhenScopesAreInvalid() {
        List<String> scopes =
                List.of(OIDCScopeValue.OPENID.getValue(), OIDCScopeValue.ADDRESS.getValue());
        when(tokenValidationService.validateAccessTokenSignature(accessToken)).thenReturn(true);
        when(clientService.getClient(CLIENT_ID))
                .thenReturn(Optional.of(generateClientRegistry(scopes)));

        AccessTokenException accessTokenException =
                assertThrows(
                        AccessTokenException.class,
                        () -> validationService.parse(accessToken.toAuthorizationHeader()),
                        "Expected to throw AccessTokenException");

        assertThat(accessTokenException.getMessage(), equalTo("Invalid Scopes"));
        assertThat(accessTokenException.getError(), equalTo(OAuth2Error.INVALID_SCOPE));
    }

    @Test
    void shouldThrowExceptionWhenAccessTokenNotFoundInRedis() {
        when(tokenValidationService.validateAccessTokenSignature(accessToken)).thenReturn(true);
        when(clientService.getClient(CLIENT_ID))
                .thenReturn(Optional.of(generateClientRegistry(SCOPES)));
        when(redisConnectionService.getValue(ACCESS_TOKEN_PREFIX + CLIENT_ID + "." + SUBJECT))
                .thenReturn(null);

        AccessTokenException accessTokenException =
                assertThrows(
                        AccessTokenException.class,
                        () -> validationService.parse(accessToken.toAuthorizationHeader()),
                        "Expected to throw AccessTokenException");

        assertThat(accessTokenException.getMessage(), equalTo("Invalid Access Token"));
        assertThat(accessTokenException.getError(), equalTo(BearerTokenError.INVALID_TOKEN));
    }

    @Test
    void shouldThrowExceptionWhenAccessTokenSentIsNotTheSameAsInRedis()
            throws JOSEException, JsonProcessingException {
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

        AccessTokenException accessTokenException =
                assertThrows(
                        AccessTokenException.class,
                        () -> validationService.parse(accessToken.toAuthorizationHeader()),
                        "Expected to throw AccessTokenException");

        assertThat(accessTokenException.getMessage(), equalTo("Invalid Access Token"));
        assertThat(accessTokenException.getError(), equalTo(BearerTokenError.INVALID_TOKEN));
    }

    @Test
    void shouldThrowExceptionWhenUnableToParseAccessToken() {
        AccessTokenException accessTokenException =
                assertThrows(
                        AccessTokenException.class,
                        () -> validationService.parse("rubbish-access-token"),
                        "Expected to throw AccessTokenException");

        assertThat(accessTokenException.getMessage(), equalTo("Unable to parse AccessToken"));
        assertThat(accessTokenException.getError(), equalTo(BearerTokenError.INVALID_TOKEN));
    }

    private ClientRegistry generateClientRegistry(List<String> scopes) {
        return new ClientRegistry()
                .setRedirectUrls(singletonList("http://localhost/redirect"))
                .setClientID(CLIENT_ID)
                .setContacts(singletonList("joe.bloggs@digital.cabinet-office.gov.uk"))
                .setPublicKey(null)
                .setScopes(scopes);
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
}
