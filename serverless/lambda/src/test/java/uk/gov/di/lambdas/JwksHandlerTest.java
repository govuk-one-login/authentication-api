package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.services.TokenService;

import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventStatusMatcher.hasStatus;

class JwksHandlerTest {

    private final Context context = mock(Context.class);
    private final TokenService tokenService = mock(TokenService.class);
    private JwksHandler handler;

    @BeforeEach
    public void setUp() {
        handler = new JwksHandler(tokenService);
    }

    @Test
    public void shouldReturn200WhenRequestIsSuccessful() throws JOSEException {
        JWK signingKey = new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
        when(tokenService.getSigningKey()).thenReturn(signingKey);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        JWKSet expectedJWKSet = new JWKSet(signingKey);

        assertThat(result, hasStatus(200));
        assertEquals(expectedJWKSet.toString(true), result.getBody());
    }

    @Test
    public void shouldReturn500WhenSigningKeyIsNotPresent() {
        when(tokenService.getSigningKey()).thenReturn(null);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(500));
        assertEquals("Signing key is not present", result.getBody());
    }
}
