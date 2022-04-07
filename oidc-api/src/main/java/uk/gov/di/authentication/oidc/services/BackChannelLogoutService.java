package uk.gov.di.authentication.oidc.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.entity.BackChannelLogoutMessage;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import static org.apache.logging.log4j.util.Strings.isBlank;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class BackChannelLogoutService {

    private static final Logger LOGGER = LogManager.getLogger(BackChannelLogoutService.class);
    private final AwsSqsClient awsSqsClient;

    public BackChannelLogoutService(ConfigurationService configurationService) {
        this(
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getBackChannelLogoutQueueUri(),
                        configurationService.getSqsEndpointUri()));
    }

    public BackChannelLogoutService(AwsSqsClient awsSqsClient) {
        this.awsSqsClient = awsSqsClient;
    }

    public void sendLogoutMessage(ClientRegistry clientRegistry) {

        if (isBlank(clientRegistry.getClientID())
                || isBlank(clientRegistry.getBackChannelLogoutUri())) {
            LOGGER.error("Client missing required fields");
            return;
        }

        attachLogFieldToLogs(CLIENT_ID, clientRegistry.getClientID());

        LOGGER.info("Sending logout message");

        var message =
                new BackChannelLogoutMessage(
                        clientRegistry.getClientID(), clientRegistry.getBackChannelLogoutUri());

        try {
            awsSqsClient.send(ObjectMapperFactory.getInstance().writeValueAsString(message));
        } catch (JsonProcessingException e) {
            LOGGER.error("Unable to serialise back channel logout message: " + message);
        }
    }
}
