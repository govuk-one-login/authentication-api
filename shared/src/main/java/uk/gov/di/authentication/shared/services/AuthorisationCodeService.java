package uk.gov.di.authentication.shared.services;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.AuthCodeExchangeData;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;

import java.util.Optional;

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
        this.redisConnectionService = RedisConnectionService.getInstance(configurationService);
        this.authorisationCodeExpiry = configurationService.getAuthCodeExpiry();
        this.objectMapper = SerializationService.getInstance();
    }

    public AuthorizationCode generateAndSaveAuthorisationCode(
            String clientSessionId, String email, ClientSession clientSession) {
        LOG.info("Generating and saving AuthorisationCode");
        AuthorizationCode authorizationCode = new AuthorizationCode();
        try {
            redisConnectionService.saveWithExpiry(
                    AUTH_CODE_PREFIX.concat(authorizationCode.getValue()),
                    objectMapper.writeValueAsString(
                            new AuthCodeExchangeData()
                                    .setEmail(email)
                                    .setClientSessionId(clientSessionId)
                                    .setClientSession(clientSession)),
                    authorisationCodeExpiry);
            return authorizationCode;
        } catch (JsonException e) {
            LOG.error("Error persisting auth code to cache");
            throw new RuntimeException(e);
        }
    }

    public Optional<AuthCodeExchangeData> getExchangeDataForCode(String code) {
        return Optional.ofNullable(redisConnectionService.popValue(AUTH_CODE_PREFIX.concat(code)))
                .map(
                        s -> {
                            try {
                                return objectMapper.readValue(s, AuthCodeExchangeData.class);
                            } catch (JsonException e) {
                                LOG.error("Error deserialising auth code data from cache");
                                throw new RuntimeException(e);
                            }
                        });
    }
}
