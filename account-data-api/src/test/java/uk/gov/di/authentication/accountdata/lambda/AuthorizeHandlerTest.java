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
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.accountdata.helpers.TokenGeneratorHelper;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

class AuthorizeHandlerTest {
    private static final String KEY_ID = "14342354354353";
    private final Context context = mock(Context.class);

    @Test
    void authorizeHandlerShouldAllowNonExpiredToken() throws JOSEException {
        var handler = new AuthorizeHandler();

        var fiveMinutesFromNow = Instant.now().plus(5, ChronoUnit.MINUTES);
        var bearerAccessToken = createBearerAccessTokenWithExpiry(Date.from(fiveMinutesFromNow));

        var event = new APIGatewayCustomAuthorizerEvent();
        event.setAuthorizationToken(bearerAccessToken.toAuthorizationHeader());

        var result = handler.handleRequest(event, context);

        assertEquals(200, result.getStatusCode());
    }

    @Test
    void authorizeHandlerShouldRejectExpiredToken() throws JOSEException {
        var handler = new AuthorizeHandler();

        var yesterdayInstant = Instant.now().minus(1, ChronoUnit.DAYS);
        var bearerAccessToken = createBearerAccessTokenWithExpiry(Date.from(yesterdayInstant));

        var event = new APIGatewayCustomAuthorizerEvent();
        event.setAuthorizationToken(bearerAccessToken.toAuthorizationHeader());
        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(event, context),
                        "Expected to throw exception");

        assertEquals("Unauthorized", exception.getMessage());
    }

    private static BearerAccessToken createBearerAccessTokenWithExpiry(Date expiryDate)
            throws JOSEException {
        ECKey ecJWK = new ECKeyGenerator(Curve.P_256).keyID(KEY_ID).generate();
        JWSSigner signer = new ECDSASigner(ecJWK);
        var signedToken = TokenGeneratorHelper.generateSignedToken(signer, KEY_ID, expiryDate);
        return new BearerAccessToken(signedToken.serialize());
    }
}
