package uk.gov.di.authentication.oidc.lambda;

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
import uk.gov.di.authentication.shared.services.TokenValidationService;

import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasHeader;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class JwksHandlerTest {

    private final Context context = mock(Context.class);
    private final TokenValidationService tokenValidationService =
            mock(TokenValidationService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private JwksHandler handler;

    @BeforeEach
    public void setUp() {
        handler = new JwksHandler(tokenValidationService, configurationService);
    }

    @Test
    public void shouldReturn200WhenRequestIsSuccessful() throws JOSEException {
        JWK opaqueSigningKey =
                new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
        when(tokenValidationService.getPublicJwkWithOpaqueId()).thenReturn(opaqueSigningKey);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        JWKSet expectedJWKSet = new JWKSet(opaqueSigningKey);

        assertThat(result, hasStatus(200));
        assertThat(result, hasBody(expectedJWKSet.toString(true)));
    }

    @Test
    public void shouldReturn500WhenSigningKeyIsNotPresent() {
        when(tokenValidationService.getPublicJwkWithOpaqueId()).thenReturn(null);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(500));
        assertThat(result, hasBody("Error providing JWKs data"));
    }

    @Test
    public void shouldSetACacheHeaderOfOneDayOnSuccess() throws JOSEException {
        JWK opaqueSigningKey =
                new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
        when(tokenValidationService.getPublicJwkWithOpaqueId()).thenReturn(opaqueSigningKey);

        var response = handler.handleRequest(new APIGatewayProxyRequestEvent(), context);
        assertThat(response, hasHeader("Cache-Control", "max-age=86400"));
    }
}
