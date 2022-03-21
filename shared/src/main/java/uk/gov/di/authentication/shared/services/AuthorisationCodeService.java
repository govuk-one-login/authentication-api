package uk.gov.di.authentication.shared.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.AuthCodeExchangeData;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;

import java.util.Optional;

public class AuthorisationCodeService {

    private static final Logger LOG = LogManager.getLogger(AuthorisationCodeService.class);
    public static final String AUTH_CODE_PREFIX = "auth-code-";

    private final RedisConnectionService redisConnectionService;
    private final long authorisationCodeExpiry;
    private final ObjectMapper objectMapper;

    public AuthorisationCodeService(ConfigurationService configurationService) {
        this.redisConnectionService =
                new RedisConnectionService(
                        configurationService.getRedisHost(),
                        configurationService.getRedisPort(),
                        configurationService.getUseRedisTLS(),
                        configurationService.getRedisPassword());
        this.authorisationCodeExpiry = configurationService.getAuthCodeExpiry();
        this.objectMapper = ObjectMapperFactory.getInstance();
    }

    public AuthorizationCode generateAuthorisationCode(
            String clientSessionId, String email, ClientSession clientSession) {
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
        } catch (JsonProcessingException e) {
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
                            } catch (JsonProcessingException e) {
                                LOG.error("Error deserialising auth code data from cache");
                                throw new RuntimeException(e);
                            }
                        });
    }
}
