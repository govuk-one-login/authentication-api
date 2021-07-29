package uk.gov.di.services;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

public class AuthorisationCodeService {

    private static final Logger LOG = LoggerFactory.getLogger(AuthorisationCodeService.class);
    public static final String AUTH_CODE_PREFIX = "auth-code-";

    private final RedisConnectionService redisConnectionService;
    private final long authorisationCodeExpiry;

    public AuthorisationCodeService(ConfigurationService configurationService) {
        this.redisConnectionService =
                new RedisConnectionService(
                        configurationService.getRedisHost(),
                        configurationService.getRedisPort(),
                        configurationService.getUseRedisTLS(),
                        configurationService.getRedisPassword());
        this.authorisationCodeExpiry = configurationService.getAuthCodeExpiry();
    }

    public AuthorizationCode generateAuthorisationCode(String clientSessionId) {
        AuthorizationCode authorizationCode = new AuthorizationCode();
        redisConnectionService.saveWithExpiry(
                AUTH_CODE_PREFIX.concat(authorizationCode.getValue()),
                clientSessionId,
                authorisationCodeExpiry);
        return authorizationCode;
    }

    public Optional<String> getClientSessionIdForCode(String code) {
        return Optional.ofNullable(redisConnectionService.popValue(AUTH_CODE_PREFIX.concat(code)));
    }
}
