package uk.gov.di.authentication.oidc.services;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.OIDCError;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.exceptions.AuthenticationCallbackValidationException;
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
        var value =
                Optional.ofNullable(
                        redisConnectionService.getValue(
                                AUTHENTICATION_STATE_STORAGE_PREFIX + sessionId));

        var dynamoState =
                stateStorageService.getState(AUTHENTICATION_STATE_STORAGE_PREFIX + sessionId);

        logComparisonBetweenStateValues(value, dynamoState);
        if (value.isEmpty()) {
            LOG.info("No Authentication state found in Redis");
            return false;
        }
        State redisState;
        try {
            redisState = objectMapper.readValue(value.get(), State.class);
        } catch (JsonException e) {
            LOG.info("Error when deserializing state from redis");
            return false;
        }
        LOG.info(
                "Response state: {} and Stored state: {}. Are equal: {}",
                responseState,
                redisState.getValue(),
                responseState.equals(redisState.getValue()));
        return responseState.equals(redisState.getValue());
    }

    private void logComparisonBetweenStateValues(
            Optional<String> redisStateOpt, Optional<State> dynamoStateOpt) {
        try {
            if (redisStateOpt.isEmpty() && dynamoStateOpt.isEmpty()) {
                LOG.info("Both redis and dynamo state are empty");
                return;
            }
            if (redisStateOpt.isPresent() && dynamoStateOpt.isEmpty()
                    || redisStateOpt.isEmpty() && dynamoStateOpt.isPresent()) {
                LOG.info(
                        "Either one of redis or Dynamo state is not present. Redis present: {}, Dynamo present: {}",
                        redisStateOpt.isPresent(),
                        dynamoStateOpt.isPresent());
                return;
            }

            var redisState = objectMapper.readValue(redisStateOpt.get(), State.class);
            var dyanmoState = dynamoStateOpt.get();

            LOG.info(
                    "Dynamo state: {} and redis state: {}. Are equal: {}",
                    dyanmoState.getValue(),
                    redisState.getValue(),
                    dyanmoState.getValue().equals(redisState.getValue()));

        } catch (Exception e) {
            LOG.warn(
                    "Exception when comparing redis and dynamo state: {}. Continuing as normal",
                    e.getMessage());
        }
    }
}
