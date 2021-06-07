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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwksHandlerTest {

    private final Context CONTEXT = mock(Context.class);
    private JwksHandler handler;
    private final TokenService TOKEN_SERVICE = mock(TokenService.class);

    @BeforeEach
    public void setUp() {
        handler = new JwksHandler(TOKEN_SERVICE);
    }

    @Test
    public void shouldReturn200WhenRequestIsSuccessful() throws JOSEException {
        JWK signingKey = new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
        when(TOKEN_SERVICE.getSigningKey()).thenReturn(signingKey);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, CONTEXT);

        JWKSet expectedJWKSet = new JWKSet(signingKey);

        assertEquals(200, result.getStatusCode());
        assertEquals(expectedJWKSet.toString(true), result.getBody());
    }

    @Test
    public void shouldReturn500WhenSigningKeyIsNotPresent() {
        when(TOKEN_SERVICE.getSigningKey()).thenReturn(null);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, CONTEXT);

        assertEquals(500, result.getStatusCode());
        assertEquals("Signing key is not present", result.getBody());
    }
}