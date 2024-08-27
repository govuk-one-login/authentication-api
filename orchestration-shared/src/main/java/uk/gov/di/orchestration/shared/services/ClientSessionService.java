package uk.gov.di.orchestration.shared.services;

import com.google.gson.JsonSyntaxException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.VtrList;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.helpers.JsonUpdateHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.serialization.Json.JsonException;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.text.MessageFormat.format;
import static uk.gov.di.orchestration.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;
import static uk.gov.di.orchestration.shared.helpers.RequestHeaderHelper.headersContainValidHeader;

public class ClientSessionService {

    private static final Logger LOG = LogManager.getLogger(ClientSessionService.class);
    public static final String CLIENT_SESSION_PREFIX = "client-session-";

    private final RedisConnectionService redisConnectionService;
    private final ConfigurationService configurationService;
    private final Json objectMapper;

    public ClientSessionService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.redisConnectionService =
                new RedisConnectionService(
                        configurationService.getRedisHost(),
                        configurationService.getRedisPort(),
                        configurationService.getUseRedisTLS(),
                        configurationService.getRedisPassword());
        objectMapper = SerializationService.getInstance();
    }

    public ClientSessionService(
            ConfigurationService configurationService,
            RedisConnectionService redisConnectionService) {
        this.configurationService = configurationService;
        this.redisConnectionService = redisConnectionService;
        objectMapper = SerializationService.getInstance();
    }

    public ClientSession generateClientSession(
            Map<String, List<String>> authRequestParams,
            LocalDateTime creationDate,
            VtrList vtrList,
            String clientName) {
        return new ClientSession(authRequestParams, creationDate, vtrList, clientName);
    }

    public void storeClientSession(String clientSessionId, ClientSession clientSession) {
        try {
            redisConnectionService.saveWithExpiry(
                    CLIENT_SESSION_PREFIX.concat(clientSessionId),
                    objectMapper.writeValueAsString(clientSession),
                    configurationService.getSessionExpiry());
        } catch (JsonException e) {
            LOG.error("Error saving client session to Redis");
            throw new RuntimeException(e);
        }
        LOG.info("Generated new ClientSession");
    }

    public String generateClientSessionId() {
        return IdGenerator.generate();
    }

    public Optional<ClientSession> getClientSession(String clientSessionId) {
        attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);
        attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, clientSessionId);

        try {
            if (redisConnectionService.keyExists(CLIENT_SESSION_PREFIX.concat(clientSessionId))) {
                return Optional.of(
                        objectMapper.readValue(
                                redisConnectionService.getValue(
                                        CLIENT_SESSION_PREFIX.concat(clientSessionId)),
                                ClientSession.class));
            } else {
                LOG.warn("Client session with given key is not present in redis");
                return Optional.empty();
            }
        } catch (JsonException e) {
            LOG.error("Unable to deserialize client session from redis");
            throw new RuntimeException(e);
        }
    }

    public void updateStoredClientSession(String clientSessionId, ClientSession clientSession) {
        attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);
        attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, clientSessionId);

        var clientSessionKey = CLIENT_SESSION_PREFIX.concat(clientSessionId);

        if (!redisConnectionService.keyExists(clientSessionKey)) {
            LOG.error(
                    "Couldn't update client session with given key as it was not present in redis");
            throw new IllegalArgumentException(
                    format("Client session with ID {0} not found.", clientSessionId));
        }

        try {
            var oldClientSession = redisConnectionService.getValue(clientSessionKey);
            var newClientSession = objectMapper.writeValueAsString(clientSession);
            var updatedClientSession =
                    JsonUpdateHelper.updateJson(oldClientSession, newClientSession);
            var expiry = configurationService.getSessionExpiry();
            redisConnectionService.saveWithExpiry(clientSessionKey, updatedClientSession, expiry);
        } catch (JsonException | JsonSyntaxException e) {
            LOG.error("Error saving client session to Redis");
            throw new RuntimeException(e);
        }
    }

    public void deleteStoredClientSession(String clientSessionId) {
        redisConnectionService.deleteValue(clientSessionId);
    }

    public Optional<ClientSession> getClientSessionFromRequestHeaders(Map<String, String> headers) {
        if (!headersContainValidHeader(
                headers,
                CLIENT_SESSION_ID_HEADER,
                configurationService.getHeadersCaseInsensitive())) {
            return Optional.empty();
        }
        String clientSessionId =
                getHeaderValueFromHeaders(
                        headers,
                        CLIENT_SESSION_ID_HEADER,
                        configurationService.getHeadersCaseInsensitive());
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
