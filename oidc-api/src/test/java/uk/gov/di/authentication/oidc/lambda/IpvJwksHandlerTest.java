package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.ipv.lambda.IpvJwksHandler;
import uk.gov.di.orchestration.shared.services.JwksService;

import java.util.List;
import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasHeader;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class IpvJwksHandlerTest {
    private final Context context = mock(Context.class);
    private final JwksService jwksService = mock(JwksService.class);
    private IpvJwksHandler handler;
    private final ECKey ipvTokenSigningKey =
            new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate();
    private final ECKey orchIpvTokenSigningKey =
            new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate();

    IpvJwksHandlerTest() throws JOSEException {}

    @BeforeEach
    public void setUp() {
        handler = new IpvJwksHandler(jwksService);

        when(jwksService.getPublicIpvTokenJwkWithOpaqueId()).thenReturn(ipvTokenSigningKey);
        when(jwksService.getPublicOrchIpvTokenJwkWithOpaqueId()).thenReturn(orchIpvTokenSigningKey);
    }

    @Test
    void shouldReturnOnlyAuthIpvJwkWhenAuthIpvJwkPublishEnabledAndOrchIpvJwkPublishDisabled() {
        when(jwksService.isAuthIpvTokenSigningKeyPublishEnabled()).thenReturn(true);
        when(jwksService.isOrchIpvTokenSigningKeyPublishEnabled()).thenReturn(false);

        var event = new APIGatewayProxyRequestEvent();
        var result = handler.handleRequest(event, context);

        var expectedJWKSet = new JWKSet(List.of(ipvTokenSigningKey));

        assertThat(result, hasStatus(200));
        assertThat(result, hasBody(expectedJWKSet.toString(true)));
    }

    @Test
    void shouldReturnOnlyOrchIpvJwkWhenAuthIpvJwkPublishDisabledAndOrchIpvJwkPublishEnabled() {
        when(jwksService.isAuthIpvTokenSigningKeyPublishEnabled()).thenReturn(false);
        when(jwksService.isOrchIpvTokenSigningKeyPublishEnabled()).thenReturn(true);

        var event = new APIGatewayProxyRequestEvent();
        var result = handler.handleRequest(event, context);

        var expectedJWKSet = new JWKSet(List.of(orchIpvTokenSigningKey));

        assertThat(result, hasStatus(200));
        assertThat(result, hasBody(expectedJWKSet.toString(true)));
    }

    @Test
    void
            shouldReturnBothAuthIpvJwkAndOrchIpvJwkWhenAuthIpvJwkPublishEnabledAndOrchIpvJwkPublishEnabled() {
        when(jwksService.isAuthIpvTokenSigningKeyPublishEnabled()).thenReturn(true);
        when(jwksService.isOrchIpvTokenSigningKeyPublishEnabled()).thenReturn(true);

        var event = new APIGatewayProxyRequestEvent();
        var result = handler.handleRequest(event, context);

        var expectedJWKSet = new JWKSet(List.of(ipvTokenSigningKey, orchIpvTokenSigningKey));

        assertThat(result, hasStatus(200));
        assertThat(result, hasBody(expectedJWKSet.toString(true)));
    }

    @Test
    void shouldReturn500WhenSigningKeyIsNotPresent() {
        when(jwksService.isAuthIpvTokenSigningKeyPublishEnabled()).thenReturn(true);

        when(jwksService.getPublicIpvTokenJwkWithOpaqueId()).thenReturn(null);

        var event = new APIGatewayProxyRequestEvent();
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(500));
        assertThat(result, hasBody("Error providing IpvJwks data"));
    }

    @Test
    void shouldReturn500WhenAuthIpvJwkPublishDisabledAndOrchIpvJwkPublishDisabled() {
        when(jwksService.isAuthIpvTokenSigningKeyPublishEnabled()).thenReturn(false);
        when(jwksService.isOrchIpvTokenSigningKeyPublishEnabled()).thenReturn(false);

        var event = new APIGatewayProxyRequestEvent();
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(500));
        assertThat(result, hasBody("Error providing IpvJwks data"));
    }

    @Test
    void shouldSetACacheHeaderOfOneDayOnSuccess() {
        when(jwksService.isAuthIpvTokenSigningKeyPublishEnabled()).thenReturn(true);

        var response = handler.handleRequest(new APIGatewayProxyRequestEvent(), context);

        assertThat(response, hasHeader("Cache-Control", "max-age=86400"));
    }
}
