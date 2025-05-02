package uk.gov.di.authentication.api;

import com.nimbusds.jose.jwk.JWKSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.ipv.lambda.IpvJwksHandler;
import uk.gov.di.orchestration.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.orchestration.sharedtest.extensions.TokenSigningExtension;

import java.text.ParseException;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static uk.gov.di.orchestration.sharedtest.helper.AuditAssertionsHelper.assertNoTxmaAuditEventsReceived;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class IpvJwksHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    @RegisterExtension
    protected static final TokenSigningExtension orchIpvPrivateKeyJwtSigner =
            new TokenSigningExtension("orch-ipv-token-auth-key");

    @Test
    void shouldReturn200AndClientInfoResponseForValidClient() throws ParseException {
        var configurationService = new IpvJwksHandlerIntegrationTest.TestConfigurationService();
        handler = new IpvJwksHandler(configurationService);
        var response = makeRequest(Optional.empty(), Map.of(), Map.of());

        assertThat(response, hasStatus(200));
        assertThat(JWKSet.parse(response.getBody()).getKeys(), hasSize(2));

        assertNoTxmaAuditEventsReceived(txmaAuditQueue);
    }

    protected static class TestConfigurationService extends IntegrationTestConfigurationService {

        private final TokenSigningExtension orchIpvPrivateKeyJwtSignerExtension;

        public TestConfigurationService() {
            super(
                    externalTokenSigner,
                    storageTokenSigner,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters);
            this.orchIpvPrivateKeyJwtSignerExtension = orchIpvPrivateKeyJwtSigner;
        }

        @Override
        public boolean isAuthIPVTokenSigningKeyPublishEnabled() {
            return true;
        }

        @Override
        public boolean isOrchIPVTokenSigningKeyPublishEnabled() {
            return true;
        }

        @Override
        public String getOrchIPVTokenSigningKeyAlias() {
            return orchIpvPrivateKeyJwtSignerExtension.getKeyAlias();
        }
    }
}
