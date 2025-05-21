package uk.gov.di.authentication.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.model.GetItemEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
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
    private final boolean useConsistentReads;

    public AuthSessionService(ConfigurationService configurationService) {
        super(AuthSessionItem.class, "auth-session", configurationService);
        this.timeToLive = configurationService.getSessionExpiry();
        this.configurationService = configurationService;
        this.useConsistentReads = configurationService.isUsingStronglyConsistentReads();
        LOG.info("Is using strongly consistent reads: {}", useConsistentReads);
    }

    public AuthSessionService(
            DynamoDbClient dynamoDbClient,
            DynamoDbTable<AuthSessionItem> dynamoDbTable,
            ConfigurationService configurationService) {
        super(dynamoDbTable, dynamoDbClient);
        this.timeToLive = configurationService.getSessionExpiry();
        this.configurationService = configurationService;
        this.useConsistentReads = configurationService.isUsingStronglyConsistentReads();
        LOG.info("Is using strongly consistent reads: {}", useConsistentReads);
    }

    public AuthSessionItem generateNewAuthSession(String sessionId) {
        return new AuthSessionItem()
                .withSessionId(sessionId)
                .withAccountState(AuthSessionItem.AccountState.UNKNOWN)
                .withTimeToLive(
                        NowHelper.nowPlus(timeToLive, ChronoUnit.SECONDS)
                                .toInstant()
                                .getEpochSecond());
    }

    public void addSession(AuthSessionItem authSessionItem) {
        try {
            put(authSessionItem);
        } catch (Exception e) {
            logAndThrowAuthSessionException(
                    "Failed to add auth session item to table", authSessionItem.getSessionId(), e);
        }
    }

    public AuthSessionItem getUpdatedPreviousSessionOrCreateNew(
            Optional<String> previousSessionId, String newSessionId) {

        try {
            Optional<AuthSessionItem> previousAuthSession = Optional.empty();
            if (previousSessionId.isPresent()) {
                previousAuthSession = getSession(previousSessionId.get());
            }

            if (previousAuthSession.isPresent()) {
                var updatedSession =
                        previousAuthSession
                                .get()
                                .withSessionId(newSessionId)
                                .withResetPasswordState(AuthSessionItem.ResetPasswordState.NONE)
                                .withResetMfaState(AuthSessionItem.ResetMfaState.NONE)
                                .withTimeToLive(
                                        NowHelper.nowPlus(timeToLive, ChronoUnit.SECONDS)
                                                .toInstant()
                                                .getEpochSecond());

                delete(previousSessionId.get());
                LOG.info(
                        "Existing Auth session updated from previousSessionId: {}, sessionId: {}",
                        previousSessionId,
                        newSessionId);

                return updatedSession;
            } else {
                LOG.info("New Auth session item created with sessionId: {}", newSessionId);
                return generateNewAuthSession(newSessionId);
            }
        } catch (Exception e) {
            LOG.error(
                    "Failed to generate new or update previous Auth session. Session ID: {}. Error message: {}",
                    newSessionId,
                    e.getMessage());
            throw new AuthSessionException(e.getMessage());
        }
    }

    @Override
    public void delete(String sessionId) {
        get(requestFor(sessionId)).ifPresent(this::delete);
    }

    public Optional<AuthSessionItem> getSession(String sessionId) {
        Optional<AuthSessionItem> authSession = Optional.empty();
        try {
            authSession = get(requestFor(sessionId));
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
            LOG.info("Updating auth session item {}", sessionItem.toLogSafeString());
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

    private GetItemEnhancedRequest requestFor(String sessionId) {
        return GetItemEnhancedRequest.builder()
                .key(Key.builder().partitionValue(sessionId).build())
                .consistentRead(useConsistentReads)
                .build();
    }
}
