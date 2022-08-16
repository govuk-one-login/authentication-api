package uk.gov.di.authentication.api;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.ipv.lambda.IPVCapacityHandler;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.authentication.ipv.domain.IPVAuditableEvent.IPV_CAPACITY_REQUESTED;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertEventTypesReceivedByBothServices;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class IPVCapacityHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    @Test
    void shouldReturn503IfIpvCapacityNotEnabled() {
        handler = new IPVCapacityHandler(capacityAwareConfiguration("0"));

        var response =
                makeRequest(Optional.empty(), Collections.emptyMap(), Collections.emptyMap());

        assertThat(response, hasStatus(503));

        assertEventTypesReceivedByBothServices(
                auditTopic, txmaAuditQueue, List.of(IPV_CAPACITY_REQUESTED));
    }

    @Test
    void shouldReturn200IfIpvCapacityEnabled() {
        handler = new IPVCapacityHandler(capacityAwareConfiguration("1"));

        var response =
                makeRequest(Optional.empty(), Collections.emptyMap(), Collections.emptyMap());

        assertThat(response, hasStatus(200));

        assertEventTypesReceivedByBothServices(
                auditTopic, txmaAuditQueue, List.of(IPV_CAPACITY_REQUESTED));
    }

    public ConfigurationService capacityAwareConfiguration(String value) {
        return new IntegrationTestConfigurationService(
                auditTopic,
                notificationsQueue,
                auditSigningKey,
                tokenSigner,
                ipvPrivateKeyJwtSigner,
                spotQueue,
                docAppPrivateKeyJwtSigner,
                configurationParameters) {
            @Override
            public boolean isTxmaAuditEnabled() {
                return true;
            }

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
