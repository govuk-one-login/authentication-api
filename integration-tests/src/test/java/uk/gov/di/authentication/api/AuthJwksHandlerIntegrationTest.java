package uk.gov.di.authentication.api;

import com.nimbusds.jose.jwk.JWKSet;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.lambda.AuthJwksHandler;
import uk.gov.di.orchestration.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.orchestration.sharedtest.basetest.IntegrationTest;

import java.text.ParseException;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthJwksHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    @Test
    void shouldReturn200WithAuthPublicSigningKey() throws ParseException {
        var configurationService =
                new IntegrationTest.IntegrationTestConfigurationService(
                        externalTokenSigner,
                        storageTokenSigner,
                        ipvPrivateKeyJwtSigner,
                        spotQueue,
                        spotRequestQueue,
                        docAppPrivateKeyJwtSigner,
                        configurationParameters);

        handler = new AuthJwksHandler(configurationService);

        var response = makeRequest(Optional.empty(), Map.of(), Map.of());

        assertThat(response, hasStatus(200));
        assertThat(JWKSet.parse(response.getBody()).getKeys(), hasSize(1));
    }
}
