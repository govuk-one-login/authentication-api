package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.exceptions.OrchSessionException;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;

public class OrchSessionService extends BaseDynamoService<OrchSessionItem> {

    private static final Logger LOG = LogManager.getLogger(OrchSessionService.class);

    private final CookieHelper cookieHelper;

    private final long timeToLive;

    public OrchSessionService(ConfigurationService configurationService) {
        super(OrchSessionItem.class, "OrchSession", configurationService);
        this.timeToLive = configurationService.getSessionExpiry();
        this.cookieHelper = new CookieHelper();
    }

    public OrchSessionService(
            DynamoDbClient dynamoDbClient,
            DynamoDbTable<OrchSessionItem> dynamoDbTable,
            ConfigurationService configurationService) {
        super(dynamoDbTable, dynamoDbClient);
        this.timeToLive = configurationService.getSessionExpiry();
        this.cookieHelper = new CookieHelper();
    }

    public void addSession(String sessionId) {
        var item =
                new OrchSessionItem()
                        .withSessionId(sessionId)
                        .withTimeToLive(
                                NowHelper.nowPlus(timeToLive, ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond());
        try {
            put(item);
        } catch (Exception e) {
            logAndThrowOrchSessionException("Failed to add Orch session item", sessionId, e);
        }
    }

    public Optional<OrchSessionItem> getSession(String sessionId) {
        Optional<OrchSessionItem> orchSession = Optional.empty();
        try {
            orchSession = get(sessionId);
        } catch (Exception e) {
            logAndThrowOrchSessionException("Failed to get Orch session item", sessionId, e);
        }
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

    public Optional<OrchSessionItem> getSessionFromSessionCookie(Map<String, String> headers) {
        try {
            Optional<CookieHelper.SessionCookieIds> ids = cookieHelper.parseSessionCookie(headers);
            return ids.flatMap(s -> getSession(s.getSessionId()));
        } catch (Exception e) {
            logAndThrowOrchSessionException(
                    "Error getting Orch session item from session cookie", null, e);
        }
        return Optional.empty();
    }

    public void updateSession(OrchSessionItem sessionItem) {
        try {
            update(sessionItem);
        } catch (Exception e) {
            logAndThrowOrchSessionException(
                    "Error updating Orch session item", sessionItem.getSessionId(), e);
        }
    }

    private void logAndThrowOrchSessionException(String message, String sessionId, Exception e) {
        LOG.error("{}. Session ID: {}. Error message: {}", message, sessionId, e.getMessage());
        throw new OrchSessionException(message);
    }
}
