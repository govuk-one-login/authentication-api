package uk.gov.di.authentication.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.model.GetItemEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.exceptions.AuthSessionException;
import uk.gov.di.authentication.shared.helpers.InputSanitiser;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getOptionalHeaderValueFromHeaders;

public class AuthSessionService extends BaseDynamoService<AuthSessionItem> {

    private static final Logger LOG = LogManager.getLogger(AuthSessionService.class);

    private static final int SESSION_REUSE_TOLERANCE_SECONDS = 1;

    private final ConfigurationService configurationService;

    private final long timeToLive;
    private final boolean useConsistentReads;

    public AuthSessionService(ConfigurationService configurationService) {
        super(AuthSessionItem.class, "auth-session", configurationService);
        this.timeToLive = configurationService.getSessionExpiry();
        this.configurationService = configurationService;
        this.useConsistentReads = configurationService.isAuthSessionUsingStronglyConsistentReads();
        LOG.info("Is using strongly consistent reads: {}", useConsistentReads);
    }

    public AuthSessionService(
            DynamoDbClient dynamoDbClient,
            DynamoDbTable<AuthSessionItem> dynamoDbTable,
            ConfigurationService configurationService) {
        super(dynamoDbTable, dynamoDbClient);
        this.timeToLive = configurationService.getSessionExpiry();
        this.configurationService = configurationService;
        this.useConsistentReads = configurationService.isAuthSessionUsingStronglyConsistentReads();
        LOG.info("Is using strongly consistent reads: {}", useConsistentReads);
    }

    public AuthSessionItem generateNewAuthSession(String sessionId) {
        return new AuthSessionItem()
                .withSessionId(sessionId)
                .withAccountState(AuthSessionItem.AccountState.UNKNOWN)
                .withCreatedAt(Instant.now().toString())
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
            Optional<String> maybePreviousSessionId, String newSessionId) {

        try {
            Optional<AuthSessionItem> previousAuthSession = Optional.empty();
            if (maybePreviousSessionId.isPresent()) {
                previousAuthSession = getSession(maybePreviousSessionId.get());
            }

            if (previousAuthSession.isPresent()) {
                var previousSessionId = maybePreviousSessionId.get();
                var updatedSession =
                        previousAuthSession
                                .get()
                                .withSessionId(newSessionId)
                                .withResetPasswordState(AuthSessionItem.ResetPasswordState.NONE)
                                .withResetMfaState(AuthSessionItem.ResetMfaState.NONE)
                                .withPreviousSessionId(previousSessionId)
                                .withCreatedAt(Instant.now().toString())
                                .withTimeToLive(
                                        NowHelper.nowPlus(timeToLive, ChronoUnit.SECONDS)
                                                .toInstant()
                                                .getEpochSecond());

                delete(previousSessionId);
                LOG.info(
                        "Existing Auth session updated from previousSessionId: {}, sessionId: {}",
                        maybePreviousSessionId,
                        newSessionId);

                return updatedSession;
            } else {
                if (maybePreviousSessionId.isPresent()) {
                    var maybeExistingSession = getSession(newSessionId);
                    var existingSessionWithNewSessionId =
                            maybeExistingSession.filter(
                                    session ->
                                            sessionIsEligibleToBeReused(
                                                    session, maybePreviousSessionId.get()));
                    if (existingSessionWithNewSessionId.isPresent()) {
                        LOG.info(
                                "Session already exists with newSessionId {} and previousSessionId {}, reusing",
                                newSessionId,
                                maybePreviousSessionId);
                        return existingSessionWithNewSessionId.get();
                    } else if (maybeExistingSession.isPresent()) {
                        var previousSessionIdOnSession =
                                maybeExistingSession.get().getPreviousSessionId();
                        LOG.info(
                                "Session already exists with newSessionId {} and stored previousSessionId {} but is not eligible to be reused",
                                newSessionId,
                                previousSessionIdOnSession);
                    }
                }

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

    private boolean sessionIsEligibleToBeReused(
            AuthSessionItem retrievedSession, String previousSessionId) {
        if (!Objects.equals(retrievedSession.getPreviousSessionId(), previousSessionId)) {
            return false;
        }

        return parseCreatedAt(retrievedSession.getCreatedAt())
                .map(
                        createdAt ->
                                createdAt.isAfter(
                                        Instant.now()
                                                .minus(
                                                        SESSION_REUSE_TOLERANCE_SECONDS,
                                                        ChronoUnit.SECONDS)))
                .orElse(false);
    }

    private Optional<Instant> parseCreatedAt(String createdAt) {
        if (createdAt == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(Instant.parse(createdAt));
        } catch (DateTimeParseException e) {
            LOG.warn("Could not parse created at {} as instant, not reusing session", createdAt);
            return Optional.empty();
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

    public void updateSessionPasskeyAssertionRequest(
            String sessionId, String assertionRequestJsonToStore) {
        var authSessionTableName = dynamoTable.tableName();
        try {
            update(
                    UpdateItemRequest.builder()
                            .tableName(authSessionTableName)
                            .key(
                                    Map.of(
                                            AuthSessionItem.ATTRIBUTE_SESSION_ID,
                                            AttributeValue.fromS(sessionId)))
                            .updateExpression(
                                    "SET #PasskeyAssertionRequest = :PasskeyAssertionRequest")
                            .conditionExpression("attribute_exists(#SessionId)")
                            .expressionAttributeNames(
                                    Map.of(
                                            "#PasskeyAssertionRequest",
                                                    AuthSessionItem
                                                            .ATTRIBUTE_PASSKEY_ASSERTION_REQUEST,
                                            "#SessionId", AuthSessionItem.ATTRIBUTE_SESSION_ID))
                            .expressionAttributeValues(
                                    Map.of(
                                            ":PasskeyAssertionRequest",
                                            AttributeValue.fromS(assertionRequestJsonToStore)))
                            .build());
        } catch (Exception e) {
            logAndThrowAuthSessionException(
                    "Failed to update Auth session passkey assertion request", sessionId, e);
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
