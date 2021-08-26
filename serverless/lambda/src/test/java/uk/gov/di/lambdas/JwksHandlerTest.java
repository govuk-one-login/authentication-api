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
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.TokenService;

import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class JwksHandlerTest {

    private final Context context = mock(Context.class);
    private final TokenService tokenService = mock(TokenService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private JwksHandler handler;

    @BeforeEach
    public void setUp() {
        handler = new JwksHandler(tokenService, configurationService);
    }

    @Test
    public void shouldReturn200WhenRequestIsSuccessful() throws JOSEException {
        JWK signingKey = new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
        when(tokenService.getPublicKey()).thenReturn(signingKey);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        JWKSet expectedJWKSet = new JWKSet(signingKey);

        assertThat(result, hasStatus(200));
        assertThat(result, hasBody(expectedJWKSet.toString(true)));
    }

    @Test
    public void shouldReturn500WhenSigningKeyIsNotPresent() {
        when(tokenService.getPublicKey()).thenReturn(null);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(500));
        assertThat(result, hasBody("Signing key is not present"));
    }
}
