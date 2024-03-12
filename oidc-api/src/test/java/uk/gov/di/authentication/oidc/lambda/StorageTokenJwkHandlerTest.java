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
import uk.gov.di.orchestration.shared.services.JwksService;

import java.util.List;
import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasHeader;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class StorageTokenJwkHandlerTest {

    private final Context context = mock(Context.class);
    private final JwksService jwksService = mock(JwksService.class);
    private StorageTokenJwkHandler handler;
    private final ECKey storageTokenSigningKey =
            new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate();

    StorageTokenJwkHandlerTest() throws JOSEException {}

    @BeforeEach
    public void setUp() {
        handler = new StorageTokenJwkHandler(jwksService);
        when(jwksService.getPublicStorageTokenJwkWithOpaqueId()).thenReturn(storageTokenSigningKey);
    }

    @Test
    void shouldReturnStorageTokenJwk() {
        var event = new APIGatewayProxyRequestEvent();
        var result = handler.handleRequest(event, context);

        var expectedJWKSet = new JWKSet(List.of(storageTokenSigningKey));

        assertThat(result, hasStatus(200));
        assertThat(result, hasBody(expectedJWKSet.toString(true)));
    }

    @Test
    void shouldReturn500WhenSigningKeyIsNotPresent() {
        when(jwksService.getPublicStorageTokenJwkWithOpaqueId()).thenReturn(null);

        var event = new APIGatewayProxyRequestEvent();
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(500));
        assertThat(result, hasBody("Error providing StorageTokenJwk data"));
    }

    @Test
    void shouldSetACacheHeaderOfOneDayOnSuccess() {
        var response = handler.handleRequest(new APIGatewayProxyRequestEvent(), context);
        assertThat(response, hasHeader("Cache-Control", "max-age=86400"));
    }
}
