package uk.gov.di.authentication.shared.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;

import java.util.Map;
import java.util.Optional;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.headersContainValidHeader;

public class ClientSessionService {

    private static final Logger LOG = LogManager.getLogger(ClientSessionService.class);
    public static final String CLIENT_SESSION_PREFIX = "client-session-";

    private final RedisConnectionService redisConnectionService;
    private final ConfigurationService configurationService;
    private final ObjectMapper objectMapper;

    public ClientSessionService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.redisConnectionService =
                new RedisConnectionService(
                        configurationService.getRedisHost(),
                        configurationService.getRedisPort(),
                        configurationService.getUseRedisTLS(),
                        configurationService.getRedisPassword());
        objectMapper = ObjectMapperFactory.getInstance();
    }

    public ClientSessionService(
            ConfigurationService configurationService,
            RedisConnectionService redisConnectionService) {
        this.configurationService = configurationService;
        this.redisConnectionService = redisConnectionService;
        objectMapper = ObjectMapperFactory.getInstance();
    }

    public String generateClientSession(ClientSession clientSession) {
        String id = IdGenerator.generate();

        attachLogFieldToLogs(CLIENT_SESSION_ID, id);

        try {
            redisConnectionService.saveWithExpiry(
                    CLIENT_SESSION_PREFIX.concat(id),
                    objectMapper.writeValueAsString(clientSession),
                    configurationService.getSessionExpiry());
        } catch (JsonProcessingException e) {
            LOG.error("Error saving client session to Redis");
            throw new RuntimeException(e);
        }
        LOG.info("Generated new ClientSession");
        return id;
    }

    public ClientSession getClientSession(String clientSessionId) {
        attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);

        try {
            String result =
                    redisConnectionService.getValue(CLIENT_SESSION_PREFIX.concat(clientSessionId));
            return objectMapper.readValue(result, ClientSession.class);
        } catch (JsonProcessingException | IllegalArgumentException e) {
            LOG.error("Error getting client session from Redis");
            throw new RuntimeException(e);
        }
    }

    public void saveClientSession(String clientSessionId, ClientSession clientSession) {
        attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);

        try {
            redisConnectionService.saveWithExpiry(
                    CLIENT_SESSION_PREFIX.concat(clientSessionId),
                    objectMapper.writeValueAsString(clientSession),
                    configurationService.getSessionExpiry());
        } catch (JsonProcessingException e) {
            LOG.error("Error saving client session to Redis");
            throw new RuntimeException(e);
        }
    }

    public void deleteClientSessionFromRedis(String clientSessionId) {
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
            LOG.error("Value not found for Client-Session-Id header");
            return Optional.empty();
        }
        try {
            return Optional.of(getClientSession(clientSessionId));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
