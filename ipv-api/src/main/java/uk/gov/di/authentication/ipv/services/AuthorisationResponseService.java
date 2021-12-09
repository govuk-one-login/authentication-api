package uk.gov.di.authentication.ipv.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.State;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;

import java.util.Map;
import java.util.Optional;

public class AuthorisationResponseService {

    private static final Logger LOG = LogManager.getLogger(AuthorisationResponseService.class);
    private final ConfigurationService configurationService;
    private final RedisConnectionService redisConnectionService;
    public static final String STATE_STORAGE_PREFIX = "state:";

    public AuthorisationResponseService(
            ConfigurationService configurationService,
            RedisConnectionService redisConnectionService) {
        this.configurationService = configurationService;
        this.redisConnectionService = redisConnectionService;
    }

    public Optional<ErrorObject> validateResponse(Map<String, String> headers, String sessionId) {
        if (headers == null || headers.isEmpty()) {
            LOG.warn("No Query parameters in IPV Authorisation response");
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE, "No query parameters present"));
        }
        if (headers.containsKey("error")) {
            LOG.warn("Error response found in IPV Authorisation response");
            return Optional.of(new ErrorObject(headers.get("error")));
        }
        if (!headers.containsKey("state") || headers.get("state").isEmpty()) {
            LOG.warn("No state param in IPV Authorisation response");
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "No state param present in Authorisation response"));
        }
        if (!isStateValid(sessionId, headers.get("state"))) {
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "Invalid state param present in Authorisation response"));
        }
        if (!headers.containsKey("code") || headers.get("code").isEmpty()) {
            LOG.warn("No code param in IPV Authorisation response");
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "No code param present in Authorisation response"));
        }

        return Optional.empty();
    }

    public void storeState(String sessionId, State state) {
        try {
            redisConnectionService.saveWithExpiry(
                    STATE_STORAGE_PREFIX + sessionId,
                    new ObjectMapper().writeValueAsString(state),
                    configurationService.getSessionExpiry());
        } catch (JsonProcessingException e) {
            LOG.error("Unable to state to Redis");
            throw new RuntimeException(e);
        }
    }

    private boolean isStateValid(String sessionId, String responseState) {
        var value = redisConnectionService.getValue(STATE_STORAGE_PREFIX + sessionId);
        if (value == null) {
            return false;
        }
        State storedState;
        try {
            storedState = new ObjectMapper().readValue(value, State.class);
        } catch (JsonProcessingException e) {
            return false;
        }
        return responseState.equals(storedState.getValue());
    }
}
