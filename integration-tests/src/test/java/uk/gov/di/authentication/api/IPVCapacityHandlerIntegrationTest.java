package uk.gov.di.authentication.api;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.ipv.lambda.IPVCapacityHandler;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.IPV_CAPACITY_REQUESTED;
import static uk.gov.di.orchestration.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class IPVCapacityHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    @Test
    void shouldReturn503IfIpvCapacityNotEnabled() {
        handler = new IPVCapacityHandler(capacityAwareConfiguration("0"));

        var response =
                makeRequest(Optional.empty(), Collections.emptyMap(), Collections.emptyMap());

        assertThat(response, hasStatus(503));

        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(IPV_CAPACITY_REQUESTED));
    }

    @Test
    void shouldReturn200IfIpvCapacityEnabled() {
        handler = new IPVCapacityHandler(capacityAwareConfiguration("1"));

        var response =
                makeRequest(Optional.empty(), Collections.emptyMap(), Collections.emptyMap());

        assertThat(response, hasStatus(200));

        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(IPV_CAPACITY_REQUESTED));
    }

    public ConfigurationService capacityAwareConfiguration(String value) {
        return new IntegrationTestConfigurationService(
                externalTokenSigner,
                storageTokenSigner,
                ipvPrivateKeyJwtSigner,
                spotQueue,
                spotRequestQueue,
                docAppPrivateKeyJwtSigner,
                configurationParameters) {

            @Override
            public String getTxmaAuditQueueUrl() {
                return txmaAuditQueue.getQueueUrl();
            }

            @Override
            public Optional<String> getIPVCapacity() {
                return Optional.of(value);
            }
        };
    }
}
