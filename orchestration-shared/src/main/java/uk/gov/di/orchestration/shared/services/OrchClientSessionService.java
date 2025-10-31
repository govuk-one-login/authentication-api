package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.OrchClientSessionException;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.orchestration.shared.helpers.NowHelper.NowClock;
import static uk.gov.di.orchestration.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;
import static uk.gov.di.orchestration.shared.helpers.RequestHeaderHelper.headersContainValidHeader;

public class OrchClientSessionService extends BaseDynamoService<OrchClientSessionItem> {
    private static final Logger LOG = LogManager.getLogger(OrchClientSessionService.class);

    private final ConfigurationService configurationService;
    private final long timeToLive;
    private final NowClock nowClock;

    public OrchClientSessionService(ConfigurationService configurationService) {
        this(configurationService, Clock.systemUTC());
    }

    public OrchClientSessionService(ConfigurationService configurationService, Clock clock) {
        super(OrchClientSessionItem.class, "Client-Session", configurationService, true);
        this.configurationService = configurationService;
        this.timeToLive = configurationService.getSessionExpiry();
        this.nowClock = new NowClock(clock);
    }

    public OrchClientSessionService(
            DynamoDbClient dynamoDbClient,
            DynamoDbTable<OrchClientSessionItem> dynamoDbTable,
            ConfigurationService configurationService) {
        super(dynamoDbTable, dynamoDbClient);
        this.configurationService = configurationService;
        this.timeToLive = configurationService.getSessionExpiry();
        this.nowClock = new NowClock(Clock.systemUTC());
    }

    public OrchClientSessionItem generateClientSession(
            String clientSessionId,
            Map<String, List<String>> authRequestParams,
            LocalDateTime creationDate,
            List<VectorOfTrust> vtrList,
            String clientName) {

        return new OrchClientSessionItem(
                clientSessionId, authRequestParams, creationDate, vtrList, clientName);
    }

    public void storeClientSession(OrchClientSessionItem clientSession) {
        var item =
                clientSession.withTimeToLive(
                        nowClock.nowPlus(timeToLive, ChronoUnit.SECONDS)
                                .toInstant()
                                .getEpochSecond());
        try {
            put(item);
        } catch (Exception e) {
            logAndThrowOrchClientSessionException(
                    "Failed to add Orch client session item",
                    clientSession.getClientSessionId(),
                    e);
        }
    }

    public Optional<OrchClientSessionItem> getClientSession(String clientSessionId) {
        Optional<OrchClientSessionItem> clientSession = Optional.empty();
        try {
            clientSession = get(clientSessionId);
        } catch (Exception e) {
            logAndThrowOrchClientSessionException(
                    "Failed to get Orch client session item", clientSessionId, e);
        }
        if (clientSession.isEmpty()) {
            LOG.info("No Orch client session item found with clientSessionId {}", clientSessionId);
            return clientSession;
        }

        Optional<OrchClientSessionItem> validOrchSession =
                clientSession.filter(
                        s -> s.getTimeToLive() > nowClock.now().toInstant().getEpochSecond());
        if (validOrchSession.isEmpty()) {
            LOG.info(
                    "Orch client session item with expired TTL found. Client Session ID: {}",
                    clientSessionId);
        }
        return validOrchSession;
    }

    public void updateStoredClientSession(OrchClientSessionItem clientSession) {
        var item =
                clientSession.withTimeToLive(
                        nowClock.nowPlus(timeToLive, ChronoUnit.SECONDS)
                                .toInstant()
                                .getEpochSecond());
        try {
            update(item);
        } catch (Exception e) {
            logAndThrowOrchClientSessionException(
                    "Error updating Orch client session item",
                    clientSession.getClientSessionId(),
                    e);
        }
    }

    public void deleteStoredClientSession(String clientSessionId) {
        try {
            delete(clientSessionId);
        } catch (Exception e) {
            logAndThrowOrchClientSessionException(
                    "Error deleting orch client session item", clientSessionId, e);
        }
    }

    private void logAndThrowOrchClientSessionException(
            String message, String sessionId, Exception e) {
        LOG.error(
                "{}. Client Session ID: {}. Error message: {}", message, sessionId, e.getMessage());
        throw new OrchClientSessionException(message);
    }

    public Optional<OrchClientSessionItem> getClientSessionFromRequestHeaders(
            Map<String, String> headers) {
        if (!headersContainValidHeader(
                headers,
                CLIENT_SESSION_ID_HEADER,
                false)) {
            return Optional.empty();
        }
        String clientSessionId =
                getHeaderValueFromHeaders(
                        headers,
                        CLIENT_SESSION_ID_HEADER,
                        false);
        if (clientSessionId == null) {
            LOG.warn("Value not found for Client-Session-Id header");
            return Optional.empty();
        }
        try {
            return getClientSession(clientSessionId);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
