package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.JwksService;

import java.util.List;
import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasHeader;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class JwksHandlerTest {

    private final Context context = mock(Context.class);
    private final JwksService jwksService = mock(JwksService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private JwksHandler handler;

    @BeforeEach
    public void setUp() {
        handler = new JwksHandler(configurationService, jwksService);
        when(configurationService.isDocAppApiEnabled()).thenReturn(false);
    }

    @Test
    public void shouldReturnMultipleJwksWhenDocAppIsEnabled() throws JOSEException {
        when(configurationService.isDocAppApiEnabled()).thenReturn(true);
        var tokenSigningKey =
                new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate();
        var docAppSigningKey =
                new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate();
        when(jwksService.getPublicTokenJwkWithOpaqueId()).thenReturn(tokenSigningKey);
        when(jwksService.getPublicDocAppSigningJwkWithOpaqueId()).thenReturn(docAppSigningKey);

        var event = new APIGatewayProxyRequestEvent();
        var result = handler.handleRequest(event, context);

        var expectedJWKSet = new JWKSet(List.of(tokenSigningKey, docAppSigningKey));

        assertThat(result, hasStatus(200));
        assertThat(result, hasBody(expectedJWKSet.toString(true)));
    }

    @Test
    public void shouldReturn200WhenRequestIsSuccessful() throws JOSEException {
        var opaqueSigningKey =
                new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate();
        when(jwksService.getPublicTokenJwkWithOpaqueId()).thenReturn(opaqueSigningKey);

        var event = new APIGatewayProxyRequestEvent();
        var result = handler.handleRequest(event, context);

        var expectedJWKSet = new JWKSet(opaqueSigningKey);

        assertThat(result, hasStatus(200));
        assertThat(result, hasBody(expectedJWKSet.toString(true)));
    }

    @Test
    public void shouldReturn500WhenSigningKeyIsNotPresent() {
        when(jwksService.getPublicTokenJwkWithOpaqueId()).thenReturn(null);

        var event = new APIGatewayProxyRequestEvent();
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(500));
        assertThat(result, hasBody("Error providing JWKs data"));
    }

    @Test
    public void shouldSetACacheHeaderOfOneDayOnSuccess() throws JOSEException {
        var opaqueSigningKey =
                new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate();
        when(jwksService.getPublicTokenJwkWithOpaqueId()).thenReturn(opaqueSigningKey);

        var response = handler.handleRequest(new APIGatewayProxyRequestEvent(), context);
        assertThat(response, hasHeader("Cache-Control", "max-age=86400"));
    }
}
