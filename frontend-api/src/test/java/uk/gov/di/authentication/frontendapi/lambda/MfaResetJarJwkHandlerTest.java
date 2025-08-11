package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.JwksService;

import java.util.List;
import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasHeader;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class MfaResetJarJwkHandlerTest {

    private final Context context = mock(Context.class);
    private final JwksService jwksService = mock(JwksService.class);
    private MfaResetJarJwkHandler handler;
    private final ECKey jarPublicSigningKey =
            new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate();
    private final ECKey jarDeprecatedPublicSigningKey =
            new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate();

    MfaResetJarJwkHandlerTest() throws JOSEException {}

    @BeforeEach
    public void setUp() {
        handler = new MfaResetJarJwkHandler(jwksService);
        when(jwksService.getPublicMfaResetJarJwkWithOpaqueId()).thenReturn(jarPublicSigningKey);
    }

    @Test
    void shouldReturnOnlyPrimaryMfaResetStorageTokenJwk() {
        when(jwksService.getPublicMfaResetDeprecatedJarJwkWithOpaqueId()).thenReturn(null);

        var event = new APIGatewayProxyRequestEvent();
        var result = handler.handleRequest(event, context);

        var expectedJWKSet = new JWKSet(List.of(jarPublicSigningKey));

        assertThat(result, hasStatus(200));
        assertThat(result, hasBody(expectedJWKSet.toString(true)));
        assertThat(result, hasHeader("Cache-Control", "max-age=86400"));
    }

    @Test
    void shouldReturnPrimaryAndDeprecatedMfaResetStorageTokenJwksWhenDeprecatedKeyAvailable() {
        when(jwksService.getPublicMfaResetDeprecatedJarJwkWithOpaqueId())
                .thenReturn(jarDeprecatedPublicSigningKey);

        var event = new APIGatewayProxyRequestEvent();
        var result = handler.handleRequest(event, context);

        var expectedJWKSet =
                new JWKSet(List.of(jarPublicSigningKey, jarDeprecatedPublicSigningKey));

        assertThat(result, hasStatus(200));
        assertThat(result, hasBody(expectedJWKSet.toString(true)));
        assertThat(result, hasHeader("Cache-Control", "max-age=86400"));
    }

    @Test
    void shouldReturn500WhenPrimarySigningKeyIsNotPresent() {
        when(jwksService.getPublicMfaResetJarJwkWithOpaqueId()).thenReturn(null);

        var event = new APIGatewayProxyRequestEvent();
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(500));
        assertThat(
                result,
                hasBody(
                        "Auth MFA reverification request JAR signature verification key not available."));
    }
}
