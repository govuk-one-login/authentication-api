package uk.gov.di.authentication.api;

import com.nimbusds.jose.jwk.JWKSet;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.lambda.StorageTokenJwkHandler;
import uk.gov.di.orchestration.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.text.ParseException;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static uk.gov.di.orchestration.sharedtest.helper.AuditAssertionsHelper.assertNoTxmaAuditEventsReceived;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class StorageTokenJwkIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    @Test
    void shouldReturn200AndClientInfoResponseForValidClient() throws ParseException {
        var configurationService =
                new IntegrationTestConfigurationService(
                        externalTokenSigner,
                        storageTokenSigner,
                        ipvPrivateKeyJwtSigner,
                        spotQueue,
                        spotRequestQueue,
                        docAppPrivateKeyJwtSigner,
                        configurationParameters);
        handler = new StorageTokenJwkHandler(configurationService);
        var response = makeRequest(Optional.empty(), Map.of(), Map.of());

        assertThat(response, hasStatus(200));
        assertThat(JWKSet.parse(response.getBody()).getKeys(), hasSize(1));

        assertNoTxmaAuditEventsReceived(txmaAuditQueue);
    }
}
