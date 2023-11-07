package uk.gov.di.authentication.api;

import com.nimbusds.jose.jwk.JWKSet;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.lambda.JwksHandler;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.text.ParseException;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertNoTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class JwksIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    @Test
    void shouldReturn200AndClientInfoResponseForValidClient() throws ParseException {
        var configurationService = new JwksTestConfigurationService();
        handler = new JwksHandler(configurationService);
        var response = makeRequest(Optional.empty(), Map.of(), Map.of());

        assertThat(response, hasStatus(200));
        assertThat(JWKSet.parse(response.getBody()).getKeys(), hasSize(2));

        assertNoTxmaAuditEventsReceived(txmaAuditQueue);
    }

    private static class JwksTestConfigurationService extends IntegrationTestConfigurationService {

        public JwksTestConfigurationService() {
            super(
                    auditTopic,
                    notificationsQueue,
                    auditSigningKey,
                    tokenSigner,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters);
        }
    }
}
