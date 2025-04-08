package uk.gov.di.orchestration.shared.services;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.AuthCodeExchangeData;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.serialization.Json.JsonException;

public class AuthorisationCodeService {

    private static final Logger LOG = LogManager.getLogger(AuthorisationCodeService.class);
    public static final String AUTH_CODE_PREFIX = "auth-code-";

    private final RedisConnectionService redisConnectionService;
    private final long authorisationCodeExpiry;
    private final Json objectMapper;

    public AuthorisationCodeService(
            ConfigurationService configurationService,
            RedisConnectionService redisConnectionService,
            Json objectMapper) {
        this.redisConnectionService = redisConnectionService;
        this.authorisationCodeExpiry = configurationService.getAuthCodeExpiry();
        this.objectMapper = objectMapper;
    }

    public AuthorisationCodeService(ConfigurationService configurationService) {
        this.redisConnectionService =
                new RedisConnectionService(
                        configurationService.getRedisHost(),
                        configurationService.getRedisPort(),
                        configurationService.getUseRedisTLS(),
                        configurationService.getRedisPassword());
        this.authorisationCodeExpiry = configurationService.getAuthCodeExpiry();
        this.objectMapper = SerializationService.getInstance();
    }

    public AuthorizationCode generateAndSaveAuthorisationCode(
            String clientId, String clientSessionId, String email, Long authTime) {
        LOG.info("Generating and saving AuthorisationCode");
        AuthorizationCode authorizationCode = new AuthorizationCode();
        try {
            redisConnectionService.saveWithExpiry(
                    AUTH_CODE_PREFIX.concat(authorizationCode.getValue()),
                    objectMapper.writeValueAsString(
                            new AuthCodeExchangeData()
                                    .setEmail(email)
                                    .setClientId(clientId)
                                    .setClientSessionId(clientSessionId)
                                    .setAuthTime(authTime)),
                    authorisationCodeExpiry);
            return authorizationCode;
        } catch (JsonException e) {
            LOG.error("Error persisting auth code to cache");
            throw new RuntimeException(e);
        }
    }
}
