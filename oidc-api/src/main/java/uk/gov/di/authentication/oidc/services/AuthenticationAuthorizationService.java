package uk.gov.di.authentication.oidc.services;

import com.nimbusds.oauth2.sdk.id.State;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.serialization.Json.JsonException;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;
import uk.gov.di.orchestration.shared.services.SerializationService;

import java.util.Map;
import java.util.Optional;

public class AuthenticationAuthorizationService {
    private static final Logger LOG =
            LogManager.getLogger(AuthenticationAuthorizationService.class);
    private final RedisConnectionService redisConnectionService;
    public static final String AUTHENTICATION_STATE_STORAGE_PREFIX = "auth-state:";
    private final Json objectMapper = SerializationService.getInstance();

    public AuthenticationAuthorizationService(RedisConnectionService redisConnectionService) {
        this.redisConnectionService = redisConnectionService;
    }

    public boolean validateRequest(Map<String, String> queryParams, String sessionId) {
        LOG.info("Validating authentication callback request");
        if (queryParams == null || queryParams.isEmpty()) {
            LOG.warn("No query parameters in authentication callback request");
            return false;
        }
        if (queryParams.containsKey("error")) {
            LOG.warn("Error response found in authentication callback request");
            return false;
        }
        if (!queryParams.containsKey("state") || queryParams.get("state").isEmpty()) {
            LOG.warn("No state param found in authentication callback request query parameters");
            return false;
        }
        if (!isStateValid(sessionId, queryParams.get("state"))) {
            LOG.warn("Authentication callback request state is invalid");
            return false;
        }
        if (!queryParams.containsKey("code") || queryParams.get("code").isEmpty()) {
            LOG.warn("No code param found in authentication callback request query parameters");
            return false;
        }
        LOG.info("Authentication callback request passed validation");
        return true;
    }

    private boolean isStateValid(String sessionId, String responseState) {
        var value =
                Optional.ofNullable(
                        redisConnectionService.getValue(
                                AUTHENTICATION_STATE_STORAGE_PREFIX + sessionId));
        if (value.isEmpty()) {
            LOG.info("No Authentication state found in Redis");
            return false;
        }
        State storedState;
        try {
            storedState = objectMapper.readValue(value.get(), State.class);
        } catch (JsonException e) {
            LOG.info("Error when deserializing state from redis");
            return false;
        }
        LOG.info(
                "Response state: {} and Stored state: {}. Are equal: {}",
                responseState,
                storedState.getValue(),
                responseState.equals(storedState.getValue()));
        return responseState.equals(storedState.getValue());
    }
}
