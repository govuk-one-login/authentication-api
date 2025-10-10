package uk.gov.di.authentication.oidc.services;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.OIDCError;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.exceptions.AuthenticationCallbackValidationException;
import uk.gov.di.orchestration.shared.entity.StateItem;
import uk.gov.di.orchestration.shared.services.StateStorageService;

import java.util.List;
import java.util.Map;

import static com.nimbusds.oauth2.sdk.OAuth2Error.ACCESS_DENIED_CODE;

public class AuthenticationAuthorizationService {
    private static final Logger LOG =
            LogManager.getLogger(AuthenticationAuthorizationService.class);
    private final StateStorageService stateStorageService;
    public static final String AUTHENTICATION_STATE_STORAGE_PREFIX = "auth-state:";
    public static final List<ErrorObject> reauthErrors =
            List.of(OIDCError.LOGIN_REQUIRED, OAuth2Error.ACCESS_DENIED);

    public AuthenticationAuthorizationService(StateStorageService stateStorageService) {
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
            throw new AuthenticationCallbackValidationException(
                    new ErrorObject(
                            ACCESS_DENIED_CODE,
                            "Access denied for security reasons, a new authentication request may be successful"));
        }
        if (!queryParams.containsKey("code") || queryParams.get("code").isEmpty()) {
            LOG.warn("No code param found in authentication callback request query parameters");
            throw new AuthenticationCallbackValidationException();
        }
        LOG.info("Authentication callback request passed validation");
    }

    private boolean isStateValid(String sessionId, String responseState) {
        var valueFromDynamo =
                stateStorageService
                        .getState(AUTHENTICATION_STATE_STORAGE_PREFIX + sessionId)
                        .map(StateItem::getState);
        if (valueFromDynamo.isEmpty()) {
            LOG.info("No Authentication state found in Dynamo");
            return false;
        }

        State storedState = new State(valueFromDynamo.get());
        LOG.info(
                "Response state: {} and Stored state: {}. Are equal: {}",
                responseState,
                storedState.getValue(),
                responseState.equals(storedState.getValue()));
        return responseState.equals(storedState.getValue());
    }
}
