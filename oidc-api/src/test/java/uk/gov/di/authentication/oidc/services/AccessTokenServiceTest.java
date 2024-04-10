package uk.gov.di.authentication.oidc.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.orchestration.shared.entity.AccessTokenStore;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.exceptions.AccessTokenException;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.TokenValidationService;
import uk.gov.di.orchestration.sharedtest.helper.TokenGeneratorHelper;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withMessageContaining;

class AccessTokenServiceTest {
    private AccessTokenService validationService;
    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private final TokenValidationService tokenValidationService =
            mock(TokenValidationService.class);
    private final DynamoClientService clientService = mock(DynamoClientService.class);
    private static final Subject INTERNAL_SUBJECT = new Subject("internal-subject");
    private static final Subject INTERNAL_PAIRWISE_SUBJECT = new Subject();
    private static final Subject SUBJECT = new Subject("some-subject");
    private static final List<String> SCOPES =
            List.of(
                    OIDCScopeValue.OPENID.getValue(),
                    OIDCScopeValue.EMAIL.getValue(),
                    OIDCScopeValue.PHONE.getValue());
    private static final String CLIENT_ID = "client-id";
    private static final String BASE_URL = "https://example.com";
    private static final String KEY_ID = "14342354354353";
    private static final String ACCESS_TOKEN_PREFIX = "ACCESS_TOKEN:";
    private static final Json objectMapper = SerializationService.getInstance();
    private final ClaimsSetRequest claimsSetRequest =
            new ClaimsSetRequest()
                    .add(ValidClaims.ADDRESS.getValue())
                    .add(ValidClaims.PASSPORT.getValue())
                    .add(ValidClaims.DRIVING_PERMIT.getValue())
                    .add(ValidClaims.SOCIAL_SECURITY_RECORD.getValue())
                    .add(ValidClaims.CORE_IDENTITY_JWT.getValue())
                    .add(ValidClaims.RETURN_CODE.getValue());
    private final OIDCClaimsRequest oidcValidClaimsRequest =
            new OIDCClaimsRequest().withUserInfoClaimsRequest(claimsSetRequest);
    private AccessToken accessToken = createSignedAccessToken(null, false);

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(AccessTokenService.class);

    @BeforeEach
    void setUp() {
        validationService =
                new AccessTokenService(
                        redisConnectionService, clientService, tokenValidationService);
    }

    @AfterEach
    void tearDown() {
        assertThat(
                logging.events(),
                not(hasItem(withMessageContaining(CLIENT_ID, SUBJECT.toString()))));
    }

    @Test
    void shouldReturnAccessTokenInfoWhenAccessTokenIsValid()
            throws Json.JsonException, AccessTokenException {
        accessToken = createSignedAccessToken(oidcValidClaimsRequest, false);
        List<String> expectedIdentityClaims =
                oidcValidClaimsRequest.getUserInfoClaimsRequest().getEntries().stream()
                        .map(ClaimsSetRequest.Entry::getClaimName)
                        .collect(Collectors.toList());
        when(tokenValidationService.validateAccessTokenSignature(accessToken)).thenReturn(true);
        when(clientService.getClient(CLIENT_ID))
                .thenReturn(Optional.of(generateClientRegistry(SCOPES, true)));
        when(redisConnectionService.getValue(ACCESS_TOKEN_PREFIX + CLIENT_ID + "." + SUBJECT))
                .thenReturn(
                        objectMapper.writeValueAsString(
                                new AccessTokenStore(
                                        accessToken.getValue(),
                                        INTERNAL_SUBJECT.getValue(),
                                        INTERNAL_PAIRWISE_SUBJECT.getValue())));

        var accessTokenInfo = validationService.parse(accessToken.toAuthorizationHeader());

        assertThat(
                accessTokenInfo.getAccessTokenStore().getToken(), equalTo(accessToken.getValue()));
        assertThat(
                accessTokenInfo.getAccessTokenStore().getInternalSubjectId(),
                equalTo(INTERNAL_SUBJECT.getValue()));
        assertThat(accessTokenInfo.getSubject(), equalTo(SUBJECT.getValue()));
        assertThat(accessTokenInfo.getScopes(), equalTo(SCOPES));
        assertThat(accessTokenInfo.getIdentityClaims(), equalTo(expectedIdentityClaims));
    }

    @Test
    void shouldNotReturnIdentityClaimsWhenClientIsNotConfiguredForIdentity()
            throws Json.JsonException, AccessTokenException {
        accessToken = createSignedAccessToken(oidcValidClaimsRequest, false);
        when(tokenValidationService.validateAccessTokenSignature(accessToken)).thenReturn(true);
        when(clientService.getClient(CLIENT_ID))
                .thenReturn(Optional.of(generateClientRegistry(SCOPES, false)));
        when(redisConnectionService.getValue(ACCESS_TOKEN_PREFIX + CLIENT_ID + "." + SUBJECT))
                .thenReturn(
                        objectMapper.writeValueAsString(
                                new AccessTokenStore(
                                        accessToken.getValue(),
                                        INTERNAL_SUBJECT.getValue(),
                                        INTERNAL_PAIRWISE_SUBJECT.getValue())));

        var accessTokenInfo = validationService.parse(accessToken.toAuthorizationHeader());

        assertThat(
                accessTokenInfo.getAccessTokenStore().getToken(), equalTo(accessToken.getValue()));
        assertThat(
                accessTokenInfo.getAccessTokenStore().getInternalSubjectId(),
                equalTo(INTERNAL_SUBJECT.getValue()));
        assertThat(accessTokenInfo.getSubject(), equalTo(SUBJECT.getValue()));
        assertThat(accessTokenInfo.getScopes(), equalTo(SCOPES));
        assertThat(accessTokenInfo.getIdentityClaims(), equalTo(null));
    }

    @Test
    void shouldThrowExceptionWhenTokenSignatureIsInvalid() {
        when(tokenValidationService.validateAccessTokenSignature(accessToken)).thenReturn(false);

        var accessTokenException =
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
    void shouldThrowExceptionWhenTokenHasExpired() {
        accessToken = createSignedAccessToken(null, true);

        var accessTokenException =
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

        var accessTokenException =
                assertThrows(
                        AccessTokenException.class,
                        () -> validationService.parse(accessToken.toAuthorizationHeader()),
                        "Expected to throw AccessTokenException");

        assertThat(accessTokenException.getMessage(), equalTo("Client not found"));
        assertThat(accessTokenException.getError(), equalTo(BearerTokenError.INVALID_TOKEN));
    }

    @Test
    void shouldThrowExceptionWhenScopesAreInvalid() {
        var scopes = List.of(OIDCScopeValue.OPENID.getValue(), OIDCScopeValue.ADDRESS.getValue());
        when(tokenValidationService.validateAccessTokenSignature(accessToken)).thenReturn(true);
        when(clientService.getClient(CLIENT_ID))
                .thenReturn(Optional.of(generateClientRegistry(scopes, true)));

        var accessTokenException =
                assertThrows(
                        AccessTokenException.class,
                        () -> validationService.parse(accessToken.toAuthorizationHeader()),
                        "Expected to throw AccessTokenException");

        assertThat(accessTokenException.getMessage(), equalTo("Invalid Scopes"));
        assertThat(accessTokenException.getError(), equalTo(OAuth2Error.INVALID_SCOPE));
    }

    @Test
    void shouldThrowExceptionWhenIdentityClaimsAreInvalid() throws Json.JsonException {
        var claimsSetRequest =
                new ClaimsSetRequest().add("email").add(ValidClaims.ADDRESS.getValue());
        var invalidClaimsRequest =
                new OIDCClaimsRequest().withUserInfoClaimsRequest(claimsSetRequest);
        accessToken = createSignedAccessToken(invalidClaimsRequest, false);
        when(tokenValidationService.validateAccessTokenSignature(accessToken)).thenReturn(true);
        when(clientService.getClient(CLIENT_ID))
                .thenReturn(Optional.of(generateClientRegistry(SCOPES, true)));
        when(redisConnectionService.getValue(ACCESS_TOKEN_PREFIX + CLIENT_ID + "." + SUBJECT))
                .thenReturn(
                        objectMapper.writeValueAsString(
                                new AccessTokenStore(
                                        accessToken.getValue(),
                                        INTERNAL_SUBJECT.getValue(),
                                        INTERNAL_PAIRWISE_SUBJECT.getValue())));

        var accessTokenException =
                assertThrows(
                        AccessTokenException.class,
                        () -> validationService.parse(accessToken.toAuthorizationHeader()),
                        "Expected to throw AccessTokenException");

        assertThat(accessTokenException.getMessage(), equalTo("Invalid Identity claims"));
        assertThat(accessTokenException.getError(), equalTo(OAuth2Error.INVALID_REQUEST));
    }

    @Test
    void shouldThrowExceptionWhenAccessTokenNotFoundInRedis() {
        accessToken = createSignedAccessToken(oidcValidClaimsRequest, false);
        when(tokenValidationService.validateAccessTokenSignature(accessToken)).thenReturn(true);
        when(clientService.getClient(CLIENT_ID))
                .thenReturn(Optional.of(generateClientRegistry(SCOPES, true)));
        when(redisConnectionService.getValue(ACCESS_TOKEN_PREFIX + CLIENT_ID + "." + SUBJECT))
                .thenReturn(null);

        var accessTokenException =
                assertThrows(
                        AccessTokenException.class,
                        () -> validationService.parse(accessToken.toAuthorizationHeader()),
                        "Expected to throw AccessTokenException");

        assertThat(accessTokenException.getMessage(), equalTo("Invalid Access Token"));
        assertThat(accessTokenException.getError(), equalTo(BearerTokenError.INVALID_TOKEN));
    }

    @Test
    void shouldThrowExceptionWhenAccessTokenSentIsNotTheSameAsInRedis() throws Json.JsonException {
        accessToken = createSignedAccessToken(oidcValidClaimsRequest, false);
        when(tokenValidationService.validateAccessTokenSignature(accessToken)).thenReturn(true);
        when(clientService.getClient(CLIENT_ID))
                .thenReturn(Optional.of(generateClientRegistry(SCOPES, true)));
        when(redisConnectionService.getValue(ACCESS_TOKEN_PREFIX + CLIENT_ID + "." + SUBJECT))
                .thenReturn(
                        objectMapper.writeValueAsString(
                                new AccessTokenStore(
                                        createSignedAccessToken(null, false).getValue(),
                                        INTERNAL_SUBJECT.getValue(),
                                        INTERNAL_PAIRWISE_SUBJECT.getValue())));

        var accessTokenException =
                assertThrows(
                        AccessTokenException.class,
                        () -> validationService.parse(accessToken.toAuthorizationHeader()),
                        "Expected to throw AccessTokenException");

        assertThat(accessTokenException.getMessage(), equalTo("Invalid Access Token"));
        assertThat(accessTokenException.getError(), equalTo(BearerTokenError.INVALID_TOKEN));
    }

    @Test
    void shouldThrowExceptionWhenUnableToParseAccessToken() {
        var accessTokenException =
                assertThrows(
                        AccessTokenException.class,
                        () -> validationService.parse("rubbish-access-token"),
                        "Expected to throw AccessTokenException");

        assertThat(accessTokenException.getMessage(), equalTo("Unable to parse AccessToken"));
        assertThat(accessTokenException.getError(), equalTo(BearerTokenError.INVALID_TOKEN));
    }

    private ClientRegistry generateClientRegistry(List<String> scopes, boolean identitySupported) {
        return new ClientRegistry()
                .withRedirectUrls(singletonList("http://localhost/redirect"))
                .withClientID(CLIENT_ID)
                .withContacts(singletonList("joe.bloggs@digital.cabinet-office.gov.uk"))
                .withPublicKey(null)
                .withIdentityVerificationSupported(identitySupported)
                .withScopes(scopes);
    }

    private AccessToken createSignedAccessToken(OIDCClaimsRequest identityClaims, boolean expired) {
        try {

            var expiryDate =
                    expired
                            ? NowHelper.nowMinus(2, ChronoUnit.MINUTES)
                            : NowHelper.nowPlus(3, ChronoUnit.MINUTES);

            var ecSigningKey =
                    new ECKeyGenerator(Curve.P_256)
                            .keyID(KEY_ID)
                            .algorithm(JWSAlgorithm.ES256)
                            .generate();
            var signedJWT =
                    TokenGeneratorHelper.generateSignedToken(
                            CLIENT_ID,
                            BASE_URL,
                            SCOPES,
                            new ECDSASigner(ecSigningKey),
                            SUBJECT,
                            ecSigningKey.getKeyID(),
                            expiryDate,
                            identityClaims);
            return new BearerAccessToken(signedJWT.serialize());
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }
}
