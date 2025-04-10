package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.BackChannelLogoutMessage;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;

import java.util.Objects;

import static org.apache.logging.log4j.util.Strings.isBlank;
import static uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper.getSubject;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class BackChannelLogoutService {

    private static final Logger LOGGER = LogManager.getLogger(BackChannelLogoutService.class);
    private final AwsSqsClient awsSqsClient;
    private final AuthenticationService authenticationService;

    public BackChannelLogoutService(ConfigurationService configurationService) {
        this(
                new AwsSqsClient(
                        configurationService.getAwsRegion(),
                        configurationService.getBackChannelLogoutQueueURI(),
                        configurationService.getSqsEndpointURI()),
                new DynamoService(configurationService));
    }

    public BackChannelLogoutService(
            AwsSqsClient awsSqsClient, AuthenticationService authenticationService) {
        this.awsSqsClient = awsSqsClient;
        this.authenticationService = authenticationService;
    }

    public void sendLogoutMessage(
            ClientRegistry clientRegistry,
            String emailAddress,
            String internalSectorUri,
            String rpPairwiseId) {

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

        var subjectId =
                getSubject(user.get(), clientRegistry, authenticationService, internalSectorUri)
                        .getValue();

        if (Objects.equals(subjectId, rpPairwiseId)) {
            LOGGER.info(
                    "calculated and given rpPairwiseId are the same, client-id = {}",
                    clientRegistry.getClientID());
        } else {
            if (Objects.equals(subjectId, user.get().getPublicSubjectID())) {
                LOGGER.info(
                        "subjectId is publicSubjectId, client-id = {}",
                        clientRegistry.getClientID());
            } else if (rpPairwiseId == null) {
                LOGGER.info(
                        "rpPairwiseId on client session is null, client-id = {}",
                        clientRegistry.getClientID());
            } else if (subjectId == null) {
                LOGGER.info("subjectId is null, client-id = {}", clientRegistry.getClientID());
            } else {
                LOGGER.info(
                        "calculated and given rpPairwiseId are different, client-id = {}",
                        clientRegistry.getClientID());
            }
        }

        var message =
                new BackChannelLogoutMessage(
                        clientRegistry.getClientID(),
                        clientRegistry.getBackChannelLogoutUri(),
                        subjectId);

        awsSqsClient.sendAsync(message);
    }
}
