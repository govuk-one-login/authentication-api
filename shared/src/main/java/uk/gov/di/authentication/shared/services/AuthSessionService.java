package uk.gov.di.authentication.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.exceptions.AuthSessionException;
import uk.gov.di.authentication.shared.helpers.InputSanitiser;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getOptionalHeaderValueFromHeaders;

public class AuthSessionService extends BaseDynamoService<AuthSessionItem> {

    private static final Logger LOG = LogManager.getLogger(AuthSessionService.class);

    private final ConfigurationService configurationService;

    private final long timeToLive;

    public AuthSessionService(ConfigurationService configurationService) {
        super(AuthSessionItem.class, "auth-session", configurationService);
        this.timeToLive = configurationService.getSessionExpiry();
        this.configurationService = configurationService;
    }

    public AuthSessionService(
            DynamoDbClient dynamoDbClient,
            DynamoDbTable<AuthSessionItem> dynamoDbTable,
            ConfigurationService configurationService) {
        super(dynamoDbTable, dynamoDbClient);
        this.timeToLive = configurationService.getSessionExpiry();
        this.configurationService = configurationService;
    }

    public void addOrUpdateSessionId(Optional<String> previousSessionId, String newSessionId) {
        try {
            Optional<AuthSessionItem> oldItem = Optional.empty();
            if (previousSessionId.isPresent()) {
                LOG.info("previousSessionId is present");
                oldItem = getSession(previousSessionId.get());
            }
            if (oldItem.isPresent()) {
                AuthSessionItem newItem =
                        oldItem.get()
                                .withSessionId(newSessionId)
                                .withTimeToLive(
                                        NowHelper.nowPlus(timeToLive, ChronoUnit.SECONDS)
                                                .toInstant()
                                                .getEpochSecond());
                put(newItem);
                delete(previousSessionId.get());
                LOG.info(
                        "Session ID updated in Auth session table. previousSessionId: {}, sessionId: {}",
                        previousSessionId,
                        newSessionId);
            } else {
                AuthSessionItem newItem =
                        new AuthSessionItem()
                                .withSessionId(newSessionId)
                                .withAccountState(AuthSessionItem.AccountState.UNKNOWN)
                                .withTimeToLive(
                                        NowHelper.nowPlus(timeToLive, ChronoUnit.SECONDS)
                                                .toInstant()
                                                .getEpochSecond());
                put(newItem);
                LOG.info("New item added to Auth session table. sessionId: {}", newSessionId);
            }
        } catch (DynamoDbException e) {
            LOG.error("Failed to update or add sessionId: {}", e.getMessage());
        }
    }

    public Optional<AuthSessionItem> getSession(String sessionId) {
        Optional<AuthSessionItem> authSession = get(sessionId);

        if (authSession.isEmpty()) {
            LOG.info("No Auth session item found with sessionId {}", sessionId);
            return authSession;
        }

        Optional<AuthSessionItem> validAuthSession =
                authSession.filter(
                        s -> s.getTimeToLive() > NowHelper.now().toInstant().getEpochSecond());

        if (validAuthSession.isEmpty()) {
            LOG.info("Auth session item with expired TTL found. Session ID: {}", sessionId);
        }
        return validAuthSession;
    }

    public Optional<AuthSessionItem> getSessionFromRequestHeaders(Map<String, String> headers) {
        Optional<String> sessionId =
                getOptionalHeaderValueFromHeaders(
                        headers,
                        SESSION_ID_HEADER,
                        configurationService.getHeadersCaseInsensitive());

        if (sessionId.isEmpty()) {
            LOG.warn("Value not found for Session-Id header");
        }

        return sessionId
                .flatMap(InputSanitiser::sanitiseBase64)
                .flatMap(
                        id -> {
                            try {
                                return getSession(id);
                            } catch (Exception e) {
                                LOG.error(
                                        "Failed to retrieve session for id: {}, error: {}",
                                        id,
                                        e.getMessage());
                                throw new AuthSessionException(
                                        String.format(
                                                "Failed to get session from session store: %s",
                                                e.getMessage()));
                            }
                        });
    }

    public void updateSession(AuthSessionItem sessionItem) {
        try {
            update(sessionItem);
        } catch (DynamoDbException e) {
            LOG.error(
                    "Error updating Auth session item with id {}, Error: {}",
                    sessionItem.getSessionId(),
                    e.getMessage());
            throw e;
        }
    }
}
