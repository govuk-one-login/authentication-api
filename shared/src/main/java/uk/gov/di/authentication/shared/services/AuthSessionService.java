package uk.gov.di.authentication.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.Optional;

public class AuthSessionService extends BaseDynamoService<AuthSessionItem> {

    private static final Logger LOG = LogManager.getLogger(AuthSessionService.class);

    private final long timeToLive;

    public AuthSessionService(ConfigurationService configurationService) {
        super(AuthSessionItem.class, "auth-session", configurationService);
        this.timeToLive = 86400L; // 24 hours
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
}
