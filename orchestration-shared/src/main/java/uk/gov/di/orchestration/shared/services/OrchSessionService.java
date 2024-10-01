package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.Optional;

public class OrchSessionService extends BaseDynamoService<OrchSessionItem> {

    private static final Logger LOG = LogManager.getLogger(OrchSessionService.class);

    private final long timeToLive;

    public OrchSessionService(ConfigurationService configurationService) {
        super(OrchSessionItem.class, "OrchSession", configurationService);
        this.timeToLive = configurationService.getSessionExpiry();
    }

    public OrchSessionService(
            DynamoDbClient dynamoDbClient,
            DynamoDbTable<OrchSessionItem> dynamoDbTable,
            ConfigurationService configurationService) {
        super(dynamoDbTable, dynamoDbClient);
        this.timeToLive = configurationService.getSessionExpiry();
    }

    public void addSession(String sessionId) {
        var item =
                new OrchSessionItem()
                        .withSessionId(sessionId)
                        .withTimeToLive(
                                NowHelper.nowPlus(timeToLive, ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond());

        put(item);
    }

    public Optional<OrchSessionItem> getSession(String sessionId) {
        Optional<OrchSessionItem> orchSession = get(sessionId);

        if (orchSession.isEmpty()) {
            LOG.info("No Orch session item found with sessionId {}", sessionId);
            return orchSession;
        }

        Optional<OrchSessionItem> validOrchSession =
                orchSession.filter(
                        s -> s.getTimeToLive() > NowHelper.now().toInstant().getEpochSecond());

        if (validOrchSession.isEmpty()) {
            LOG.info("Orch session item with expired TTL found. Session ID: {}", sessionId);
        }
        return validOrchSession;
    }

    public void updateSession(OrchSessionItem sessionItem) {
        try {
            update(sessionItem);
        } catch (DynamoDbException e) {
            LOG.error(
                    "Error updating Orch session item with id {}, Error: {}",
                    sessionItem.getSessionId(),
                    e.getMessage());
            throw e;
        }
    }
}
