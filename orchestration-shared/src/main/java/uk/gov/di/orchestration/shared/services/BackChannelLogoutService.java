package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.BackChannelLogoutMessage;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;

import static org.apache.logging.log4j.util.Strings.isBlank;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class BackChannelLogoutService {

    private static final Logger LOGGER = LogManager.getLogger(BackChannelLogoutService.class);
    private final AwsSqsClient awsSqsClient;

    public BackChannelLogoutService(ConfigurationService configurationService) {
        this(
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getBackChannelLogoutQueueURI(),
                        configurationService.getSqsEndpointURI()));
    }

    public BackChannelLogoutService(AwsSqsClient awsSqsClient) {
        this.awsSqsClient = awsSqsClient;
    }

    public void sendLogoutMessage(ClientRegistry clientRegistry, String rpPairwiseId) {

        if (isBlank(clientRegistry.getClientID())
                || isBlank(clientRegistry.getBackChannelLogoutUri())) {
            LOGGER.warn("Client missing required fields");
            return;
        }

        attachLogFieldToLogs(CLIENT_ID, clientRegistry.getClientID());

        LOGGER.info("Sending logout message");

        var message =
                new BackChannelLogoutMessage(
                        clientRegistry.getClientID(),
                        clientRegistry.getBackChannelLogoutUri(),
                        rpPairwiseId);

        awsSqsClient.sendAsync(message);
    }
}
