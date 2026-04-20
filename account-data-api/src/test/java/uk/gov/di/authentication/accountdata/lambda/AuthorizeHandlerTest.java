package uk.gov.di.authentication.accountdata.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayCustomAuthorizerEvent;
import com.google.gson.Gson;
import com.google.gson.JsonParser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.accountdata.entity.AuthorizeException;
import uk.gov.di.authentication.accountdata.entity.UnauthorizedException;
import uk.gov.di.authentication.accountdata.services.RemoteJwksService;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.net.MalformedURLException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.accountdata.helpers.TokenGeneratorHelper.claimsSetBuilder;
import static uk.gov.di.authentication.accountdata.helpers.TokenGeneratorHelper.claimsSetBuilderWithoutSubject;
import static uk.gov.di.authentication.accountdata.helpers.TokenGeneratorHelper.generateSignedToken;

class AuthorizeHandlerTest {
    private static final String KEY_ID = "14342354354353";
    private final Context context = mock(Context.class);
    private final RemoteJwksService remoteJwksService = mock(RemoteJwksService.class);
    private static final Date expiryDateFiveMinutesFromNow =
            Date.from(Instant.now().plus(5, ChronoUnit.MINUTES));
    private static final String METHOD_ARN =
            "arn:aws:execute-api:eu-west-2:123456789:abc123/dev/GET/accounts";
    private static final String SUBJECT = "some-subject";

    private static ECKey ecSigningKey;
    private APIGatewayCustomAuthorizerEvent event;

    @BeforeAll
    static void setupKeyPair() throws JOSEException {
        ecSigningKey = new ECKeyGenerator(Curve.P_256).keyID(KEY_ID).generate();
    }

    @BeforeEach
    void setup() {
        event = new APIGatewayCustomAuthorizerEvent();
        event.setMethodArn(METHOD_ARN);
        when(remoteJwksService.retrieveJwkFromURLWithKeyId(KEY_ID))
                .thenReturn(Result.success(ecSigningKey.toPublicJWK()));
    }

    @AfterEach
    void resetMocks() {
        reset(remoteJwksService);
    }

    @Test
    void authorizeHandlerShouldAllowNonExpiredToken() throws JOSEException {
        var handler = new AuthorizeHandler(remoteJwksService);

        var bearerAccessToken =
                createBearerAccessTokenWithExpiry(expiryDateFiveMinutesFromNow, ecSigningKey);

        event.setAuthorizationToken(bearerAccessToken.toAuthorizationHeader());

        var result = handler.handleRequest(event, context);

        var expectedPolicyDocument =
                """
                {
                    "principalId": "%s",
                    "policyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Action": "execute-api:Invoke",
                            "Effect": "Allow",
                            "Resource": "%s"
                        }]
                    }
                }
                """
                        .formatted(SUBJECT, METHOD_ARN);

        assertEquals(
                JsonParser.parseString(expectedPolicyDocument),
                JsonParser.parseString(new Gson().toJson(result)));
    }

    @Test
    void authorizeHandlerShouldRejectMissingToken() {
        var handler = new AuthorizeHandler(remoteJwksService);

        event.setAuthorizationToken("");

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(event, context),
                        "Expected to throw exception");

        assertEquals("Unauthorized", exception.getMessage());
    }

    @Test
    void authorizeHandlerShouldRejectExpiredToken() throws JOSEException {
        var handler = new AuthorizeHandler(remoteJwksService);

        var yesterdayInstant = Instant.now().minus(1, ChronoUnit.DAYS);
        var bearerAccessToken =
                createBearerAccessTokenWithExpiry(Date.from(yesterdayInstant), ecSigningKey);

        event.setAuthorizationToken(bearerAccessToken.toAuthorizationHeader());
        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(event, context),
                        "Expected to throw exception");

        assertEquals("Unauthorized", exception.getMessage());
    }

    @Test
    void authorizeHandlerShouldRejectTokenWhoseSignatureCannotBeVerified() throws JOSEException {
        var differentKeyPair = new ECKeyGenerator(Curve.P_256).keyID(KEY_ID).generate();
        when(remoteJwksService.retrieveJwkFromURLWithKeyId(KEY_ID))
                .thenReturn(Result.success(differentKeyPair.toPublicJWK()));

        var handler = new AuthorizeHandler(remoteJwksService);

        var bearerAccessToken =
                createBearerAccessTokenWithExpiry(expiryDateFiveMinutesFromNow, ecSigningKey);

        event.setAuthorizationToken(bearerAccessToken.toAuthorizationHeader());

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(event, context),
                        "Expected to throw exception");

        assertEquals("Unauthorized", exception.getMessage());
    }

    @Test
    void authorizeHandlerShouldRejectTokenWhenJwksRetrievalFails() throws JOSEException {
        when(remoteJwksService.retrieveJwkFromURLWithKeyId(KEY_ID))
                .thenReturn(Result.failure("Failed to retrieve jwks key"));

        var handler = new AuthorizeHandler(remoteJwksService);

        var bearerAccessToken =
                createBearerAccessTokenWithExpiry(expiryDateFiveMinutesFromNow, ecSigningKey);

        event.setAuthorizationToken(bearerAccessToken.toAuthorizationHeader());

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(event, context),
                        "Expected to throw exception");

        assertEquals("Unauthorized", exception.getMessage());
    }

    @Test
    void authorizeHandlerShouldRejectUnparseableToken() {
        var handler = new AuthorizeHandler(remoteJwksService);

        event.setAuthorizationToken("Bearer not-a-valid-jwt");

        RuntimeException exception =
                assertThrows(
                        UnauthorizedException.class,
                        () -> handler.handleRequest(event, context),
                        "Expected to throw exception");

        assertEquals("Unauthorized", exception.getMessage());
    }

    @Test
    void authorizeHandlerShouldRejectAnUnsupportedAlgorithm() throws JOSEException {
        var handler = new AuthorizeHandler(remoteJwksService);

        RSAKey rsaKey = new RSAKeyGenerator(2048).keyID(KEY_ID).generate();
        JWSSigner signer = new RSASSASigner(rsaKey);

        var builder = claimsSetBuilder(SUBJECT, expiryDateFiveMinutesFromNow);
        var signedToken = generateSignedToken(signer, KEY_ID, builder);
        var token = new BearerAccessToken(signedToken.serialize());

        event.setAuthorizationToken(token.toAuthorizationHeader());

        RuntimeException exception =
                assertThrows(
                        UnauthorizedException.class,
                        () -> handler.handleRequest(event, context),
                        "Expected to throw exception");

        assertEquals("Unauthorized", exception.getMessage());
    }

    @Test
    void authorizeHandlerShouldRejectMissingSubjectId() throws JOSEException {
        var handler = new AuthorizeHandler(remoteJwksService);

        var claimsWithoutSubject = claimsSetBuilderWithoutSubject(expiryDateFiveMinutesFromNow);
        var signedToken = createBearerAccessToken(ecSigningKey, claimsWithoutSubject);
        event.setAuthorizationToken(signedToken.toAuthorizationHeader());

        RuntimeException exception =
                assertThrows(
                        UnauthorizedException.class,
                        () -> handler.handleRequest(event, context),
                        "Expected to throw exception");

        assertEquals("Unauthorized", exception.getMessage());
    }

    @Test
    void authorizeHandlerShouldRejectEmptySubjectId() throws JOSEException {
        var handler = new AuthorizeHandler(remoteJwksService);

        var claimsWithEmptySubject = claimsSetBuilder("", expiryDateFiveMinutesFromNow);
        var signedToken = createBearerAccessToken(ecSigningKey, claimsWithEmptySubject);
        event.setAuthorizationToken(signedToken.toAuthorizationHeader());

        RuntimeException exception =
                assertThrows(
                        UnauthorizedException.class,
                        () -> handler.handleRequest(event, context),
                        "Expected to throw exception");

        assertEquals("Unauthorized", exception.getMessage());
    }

    @Test
    void authorizeHandlerFailsToInitialiseWhenAccountDataJwksUrlMalformed()
            throws MalformedURLException {
        var configurationService = mock(ConfigurationService.class);
        when(configurationService.getAccountDataJwksUrl())
                .thenThrow(new MalformedURLException("uh oh"));

        assertThrows(
                AuthorizeException.class,
                () -> new AuthorizeHandler(configurationService),
                "Expected to throw exception");
    }

    private static BearerAccessToken createBearerAccessTokenWithExpiry(
            Date expiryDate, ECKey ecSigningKey) throws JOSEException {
        var claimsBuilder = claimsSetBuilder(SUBJECT, expiryDate);
        return createBearerAccessToken(ecSigningKey, claimsBuilder);
    }

    private static BearerAccessToken createBearerAccessToken(
            ECKey ecSigningKey, JWTClaimsSet.Builder claimsBuilder) throws JOSEException {
        JWSSigner signer = new ECDSASigner(ecSigningKey);
        var signedToken = generateSignedToken(signer, KEY_ID, claimsBuilder);
        return new BearerAccessToken(signedToken.serialize());
    }
}
