package uk.gov.di.authentication.accountdata.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayCustomAuthorizerEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.accountdata.entity.AuthorizeException;
import uk.gov.di.authentication.accountdata.helpers.TokenGeneratorHelper;
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

class AuthorizeHandlerTest {
    private static final String KEY_ID = "14342354354353";
    private final Context context = mock(Context.class);
    private final RemoteJwksService remoteJwksService = mock(RemoteJwksService.class);
    private static final Date expiryDateFiveMinutesFromNow =
            Date.from(Instant.now().plus(5, ChronoUnit.MINUTES));

    private static ECKey ecSigningKey;

    @BeforeAll
    static void setupKeyPair() throws JOSEException {
        ecSigningKey = new ECKeyGenerator(Curve.P_256).keyID(KEY_ID).generate();
    }

    @BeforeEach
    void setup() {
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

        var event = new APIGatewayCustomAuthorizerEvent();
        event.setAuthorizationToken(bearerAccessToken.toAuthorizationHeader());

        var result = handler.handleRequest(event, context);

        assertEquals(200, result.getStatusCode());
    }

    @Test
    void authorizeHandlerShouldRejectExpiredToken() throws JOSEException {
        var handler = new AuthorizeHandler(remoteJwksService);

        var yesterdayInstant = Instant.now().minus(1, ChronoUnit.DAYS);
        var bearerAccessToken =
                createBearerAccessTokenWithExpiry(Date.from(yesterdayInstant), ecSigningKey);

        var event = new APIGatewayCustomAuthorizerEvent();
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

        var event = new APIGatewayCustomAuthorizerEvent();
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

        var event = new APIGatewayCustomAuthorizerEvent();
        event.setAuthorizationToken(bearerAccessToken.toAuthorizationHeader());

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
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
        JWSSigner signer = new ECDSASigner(ecSigningKey);
        var signedToken = TokenGeneratorHelper.generateSignedToken(signer, KEY_ID, expiryDate);
        return new BearerAccessToken(signedToken.serialize());
    }
}
