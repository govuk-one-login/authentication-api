package uk.gov.di.authentication.oidc.services;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.OIDCError;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.exceptions.AuthenticationCallbackValidationException;
import uk.gov.di.orchestration.shared.entity.StateItem;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.serialization.Json.JsonException;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.StateStorageService;

import java.util.List;
import java.util.Map;
import java.util.Optional;

public class AuthenticationAuthorizationService {
    private static final Logger LOG =
            LogManager.getLogger(AuthenticationAuthorizationService.class);
    private final RedisConnectionService redisConnectionService;
    private final StateStorageService stateStorageService;
    public static final String AUTHENTICATION_STATE_STORAGE_PREFIX = "auth-state:";
    private final Json objectMapper = SerializationService.getInstance();
    public static final List<ErrorObject> reauthErrors =
            List.of(OIDCError.LOGIN_REQUIRED, OAuth2Error.ACCESS_DENIED);

    public AuthenticationAuthorizationService(
            RedisConnectionService redisConnectionService,
            StateStorageService stateStorageService) {
        this.redisConnectionService = redisConnectionService;
        this.stateStorageService = stateStorageService;
    }

    public void validateRequest(Map<String, String> queryParams, String sessionId)
            throws AuthenticationCallbackValidationException {
        LOG.info("Validating authentication callback request");
        if (queryParams == null || queryParams.isEmpty()) {
            LOG.warn("No query parameters in authentication callback request");
            throw new AuthenticationCallbackValidationException();
        }
        if (queryParams.containsKey("error")) {
            LOG.warn("Error response found in authentication callback request");
            var reauthError =
                    reauthErrors.stream()
                            .filter(error -> error.getCode().equals(queryParams.get("error")))
                            .findFirst();
            if (reauthError.isPresent()) {
                throw new AuthenticationCallbackValidationException(reauthError.get(), true);
            } else {
                throw new AuthenticationCallbackValidationException();
            }
        }
        if (!queryParams.containsKey("state") || queryParams.get("state").isEmpty()) {
            LOG.warn("No state param found in authentication callback request query parameters");
            throw new AuthenticationCallbackValidationException();
        }
        if (!isStateValid(sessionId, queryParams.get("state"))) {
            LOG.warn("Authentication callback request state is invalid");
            throw new AuthenticationCallbackValidationException();
        }
        if (!queryParams.containsKey("code") || queryParams.get("code").isEmpty()) {
            LOG.warn("No code param found in authentication callback request query parameters");
            throw new AuthenticationCallbackValidationException();
        }
        LOG.info("Authentication callback request passed validation");
    }

    private boolean isStateValid(String sessionId, String responseState) {
        var prefixedSessionId = AUTHENTICATION_STATE_STORAGE_PREFIX + sessionId;
        var valueFromRedis =
                Optional.ofNullable(redisConnectionService.getValue(prefixedSessionId));
        if (valueFromRedis.isEmpty()) {
            LOG.info("No Authentication state found in Redis");
            return false;
        }

        State storedState;
        try {
            storedState = objectMapper.readValue(valueFromRedis.get(), State.class);
        } catch (JsonException e) {
            LOG.info("Error when deserializing state from redis");
            return false;
        }

        // Here we have to deserialise the state and get the value before we can compare the state
        // values, as the serialised state value is surrounded by double quotes
        var valueFromDynamo =
                stateStorageService.getState(prefixedSessionId).map(StateItem::getState);
        LOG.info(
                "Is state from redis equal to state from dynamo? {}",
                valueFromDynamo.isPresent()
                        && storedState.getValue().equals(valueFromDynamo.get()));

        LOG.info(
                "Response state: {} and Stored state: {}. Are equal: {}",
                responseState,
                storedState.getValue(),
                responseState.equals(storedState.getValue()));
        return responseState.equals(storedState.getValue());
    }
}
