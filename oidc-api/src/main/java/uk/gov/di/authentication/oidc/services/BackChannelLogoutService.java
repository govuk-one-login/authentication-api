package uk.gov.di.authentication.oidc.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.entity.BackChannelLogoutMessage;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;

import static org.apache.logging.log4j.util.Strings.isBlank;
import static uk.gov.di.authentication.shared.helpers.ClientSubjectHelper.getSubject;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class BackChannelLogoutService {

    private static final Logger LOGGER = LogManager.getLogger(BackChannelLogoutService.class);
    private final AwsSqsClient awsSqsClient;
    private final AuthenticationService authenticationService;

    public BackChannelLogoutService(ConfigurationService configurationService) {
        this(
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getBackChannelLogoutQueueUri(),
                        configurationService.getSqsEndpointUri()),
                new DynamoService(configurationService));
    }

    public BackChannelLogoutService(
            AwsSqsClient awsSqsClient, AuthenticationService authenticationService) {
        this.awsSqsClient = awsSqsClient;
        this.authenticationService = authenticationService;
    }

    public void sendLogoutMessage(ClientRegistry clientRegistry, String emailAddress) {

        if (isBlank(clientRegistry.getClientID())
                || isBlank(clientRegistry.getBackChannelLogoutUri())) {
            LOGGER.warn("Client missing required fields");
            return;
        }

        attachLogFieldToLogs(CLIENT_ID, clientRegistry.getClientID());

        LOGGER.info("Sending logout message");

        var user = authenticationService.getUserProfileByEmailMaybe(emailAddress);

        if (user.isEmpty()) {
            LOGGER.warn("User does not exist");
            return;
        }

        var subjectId = getSubject(user.get(), clientRegistry, authenticationService).getValue();

        var message =
                new BackChannelLogoutMessage(
                        clientRegistry.getClientID(),
                        clientRegistry.getBackChannelLogoutUri(),
                        subjectId);

        awsSqsClient.sendAsync(message);
    }
}
