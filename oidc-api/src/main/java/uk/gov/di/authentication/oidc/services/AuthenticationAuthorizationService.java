package uk.gov.di.authentication.oidc.services;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.State;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;

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

    public Optional<ErrorObject> validateRequest(
            Map<String, String> queryParams, String sessionId) {
        LOG.info("Validating authentication callback request");
        if (queryParams == null || queryParams.isEmpty()) {
            LOG.warn("No Query parameters in authentication callback request");
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE, "No query parameters present"));
        }
        if (queryParams.containsKey("error")) {
            LOG.warn("Error response found in authentication callback request");
            return Optional.of(new ErrorObject(queryParams.get("error")));
        }
        if (!queryParams.containsKey("state") || queryParams.get("state").isEmpty()) {
            LOG.warn("No state param in authentication callback request");
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "No state param present in authentication callback request"));
        }
        if (!isStateValid(sessionId, queryParams.get("state"))) {
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "Invalid state param present in authentication callback request"));
        }
        if (!queryParams.containsKey("code") || queryParams.get("code").isEmpty()) {
            LOG.warn("No code param in authentication callback request");
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "No code param present in authentication callback request"));
        }
        LOG.info("Authentication callback request passed validation");
        return Optional.empty();
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
