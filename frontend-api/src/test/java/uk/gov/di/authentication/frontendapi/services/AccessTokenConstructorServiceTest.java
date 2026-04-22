package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.frontendapi.entity.JwtFailureReason;
import uk.gov.di.authentication.frontendapi.entity.amc.AccessTokenScope;
import uk.gov.di.authentication.frontendapi.entity.amc.AccountDataScope;
import uk.gov.di.authentication.frontendapi.entity.amc.AccountManagementScope;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.INTERNAL_PAIRWISE_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.SESSION_ID;

class AccessTokenConstructorServiceTest {

    private static final String AUDIENCE = "https://api.example.com";
    private static final String ISSUER = "https://signin.account.gov.uk/";
    private static final String AMC_CLIENT_ID = "amc-client-id";
    private static final String SIGNING_KEY_ALIAS = "test-key-alias";
    private static final long SESSION_EXPIRY = 3600L;

    private static final Instant NOW_INSTANT = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    private static final Date NOW = Date.from(NOW_INSTANT);
    private static final Date EXPIRY = Date.from(NOW_INSTANT.plus(5, ChronoUnit.MINUTES));

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final JwtService jwtService = mock(JwtService.class);

    private AccessTokenConstructorService accessTokenConstructorService;
    private ECKey signingKey;

    @BeforeEach
    void setup() throws Exception {
        accessTokenConstructorService =
                new AccessTokenConstructorService(configurationService, jwtService);

        when(configurationService.getSessionExpiry()).thenReturn(SESSION_EXPIRY);
        mockJwtSigning();
        signingKey = new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
    }

    private static Stream<Arguments> validScopes() {
        return Stream.of(
                Arguments.of(AccountDataScope.PASSKEY_CREATE, "passkey-create"),
                Arguments.of(AccountManagementScope.ACCOUNT_DELETE, "account-delete"));
    }

    @ParameterizedTest
    @MethodSource("validScopes")
    void shouldCreateAndSignAccessTokenWithValidScope(
            AccessTokenScope accessTokenScope, String expectedScope)
            throws ParseException, JOSEException {
        // Arrange
        // Act
        var result =
                accessTokenConstructorService.createSignedAccessToken(
                        INTERNAL_PAIRWISE_ID,
                        accessTokenScope,
                        SESSION_ID,
                        NOW,
                        EXPIRY,
                        AUDIENCE,
                        ISSUER,
                        AMC_CLIENT_ID,
                        SIGNING_KEY_ALIAS);

        // Assert
        assertTrue(result.isSuccess());
        var token = result.getSuccess();
        var signedJWT = SignedJWT.parse(token.getValue());
        var claims = signedJWT.getJWTClaimsSet();

        assertTrue(signedJWT.verify(new ECDSAVerifier(signingKey.toECPublicKey())));
        assertEquals(expectedScope, claims.getClaim("scope"));
        assertEquals(ISSUER, claims.getIssuer());
        assertEquals(AUDIENCE, claims.getAudience().get(0));
        assertEquals(INTERNAL_PAIRWISE_ID, claims.getSubject());
        assertEquals(AMC_CLIENT_ID, claims.getClaim("client_id"));
        assertEquals(SESSION_ID, claims.getClaim("sid"));
        assertEquals(NOW, claims.getIssueTime());
        assertEquals(EXPIRY, claims.getExpirationTime());
        assertEquals(NOW, claims.getNotBeforeTime());
    }

    @Test
    void shouldReturnJwtFailureReasonIfThereIsSigningFailure() {
        // Arrange
        when(jwtService.signJWT(any(JWTClaimsSet.class), any(String.class)))
                .thenReturn(Result.failure(JwtFailureReason.SIGNING_ERROR));

        // Act
        var result =
                accessTokenConstructorService.createSignedAccessToken(
                        INTERNAL_PAIRWISE_ID,
                        AccountDataScope.PASSKEY_CREATE,
                        SESSION_ID,
                        NOW,
                        EXPIRY,
                        AUDIENCE,
                        ISSUER,
                        AMC_CLIENT_ID,
                        SIGNING_KEY_ALIAS);

        // Assert
        assertTrue(result.isFailure());
        assertEquals(JwtFailureReason.SIGNING_ERROR, result.getFailure());
    }

    private void mockJwtSigning() {
        when(jwtService.signJWT(any(JWTClaimsSet.class), any(String.class)))
                .thenAnswer(
                        invocation -> {
                            JWTClaimsSet claims = invocation.getArgument(0);
                            var jwsBuilder =
                                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                                            .type(JOSEObjectType.JWT)
                                            .keyID(signingKey.getKeyID())
                                            .build();
                            SignedJWT signedJWT = new SignedJWT(jwsBuilder, claims);
                            signedJWT.sign(new ECDSASigner(signingKey));
                            return Result.success(signedJWT);
                        });
    }
}
