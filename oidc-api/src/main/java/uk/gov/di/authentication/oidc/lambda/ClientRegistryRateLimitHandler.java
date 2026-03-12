package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.dynamodb.ClientRegistryRateLimitService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.AWS_REQUEST_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class ClientRegistryRateLimitHandler implements RequestHandler<Object, String> {
    private final ConfigurationService configurationService;
    private ClientRegistryRateLimitService clientRegistryRateLimitService;

    public ClientRegistryRateLimitHandler() {
        this.configurationService = ConfigurationService.getInstance();
        this.clientRegistryRateLimitService =
                new ClientRegistryRateLimitService(this.configurationService);
    }

    public ClientRegistryRateLimitHandler(
            ClientRegistryRateLimitService clientRegistryRateLimitService) {
        this.configurationService = ConfigurationService.getInstance();
        this.clientRegistryRateLimitService = clientRegistryRateLimitService;
    }

    private static final Logger LOG = LogManager.getLogger(ClientRegistryRateLimitHandler.class);

    @Override
    public String handleRequest(Object ignored, Context context) {
        try {
            var clientsList = clientRegistryRateLimitService.getAllClients();
            attachLogFieldToLogs(AWS_REQUEST_ID, context.getAwsRequestId());
            LOG.info("Client List has {} items", clientsList.size());

            clientRegistryRateLimitService.updateClientsWithRateLimit(clientsList);
            LOG.info("Client Registry Rate Limits updated.");
        } catch (Exception e) {
            LOG.error("Unexpected client registry exception", e);
            throw new RuntimeException(e);
        }
        return "Done!";
    }
}
