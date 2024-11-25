package uk.gov.di.authentication.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
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

    public void addOrUpdateSessionIncludingSessionId(
            Optional<String> previousSessionId,
            String newSessionId,
            CredentialTrustLevel currentCredentialStrength) {
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
                                .withCurrentCredentialStrength(currentCredentialStrength)
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
                                .withCurrentCredentialStrength(currentCredentialStrength)
                                .withTimeToLive(
                                        NowHelper.nowPlus(timeToLive, ChronoUnit.SECONDS)
                                                .toInstant()
                                                .getEpochSecond());
                put(newItem);
                LOG.info("New item added to Auth session table. sessionId: {}", newSessionId);
            }
        } catch (Exception e) {
            logAndThrowAuthSessionException(
                    "Failed to add or update session ID of Auth session item", newSessionId, e);
        }
    }

    public Optional<AuthSessionItem> getSession(String sessionId) {
        Optional<AuthSessionItem> authSession = Optional.empty();
        try {
            authSession = get(sessionId);
        } catch (Exception e) {
            logAndThrowAuthSessionException("Failed to get Auth session item", sessionId, e);
        }
        if (authSession.isEmpty()) {
            LOG.info("No Auth session item found with session ID: {}", sessionId);
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
                                logAndThrowAuthSessionException(
                                        "Failed to get Auth session item from request headers",
                                        id,
                                        e);
                            }
                            return Optional.empty();
                        });
    }

    public void updateSession(AuthSessionItem sessionItem) {
        try {
            update(sessionItem);
        } catch (Exception e) {
            logAndThrowAuthSessionException(
                    "Failed to update Auth session item", sessionItem.getSessionId(), e);
        }
    }

    private void logAndThrowAuthSessionException(String message, String sessionId, Exception e) {
        LOG.error("{}. Session ID: {}. Error message: {}", message, sessionId, e.getMessage());
        throw new AuthSessionException(message);
    }
}
