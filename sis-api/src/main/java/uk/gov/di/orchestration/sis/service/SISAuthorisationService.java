package uk.gov.di.orchestration.sis.service;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.identity.entity.IdentityAuthConfiguration;
import uk.gov.di.orchestration.identity.services.IdentityAuthorisationService;
import uk.gov.di.orchestration.shared.entity.StateItem;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.CrossBrowserOrchestrationService;
import uk.gov.di.orchestration.shared.services.JwksCacheService;
import uk.gov.di.orchestration.shared.services.Metrics;
import uk.gov.di.orchestration.shared.services.OrchJwtService;
import uk.gov.di.orchestration.shared.services.StateStorageService;
import uk.gov.di.orchestration.shared.services.TokenService;
import uk.gov.di.orchestration.sis.exception.SISCallbackValidationError;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.nimbusds.oauth2.sdk.OAuth2Error.ACCESS_DENIED_CODE;

public class SISAuthorisationService {
    private static final String STATE_STORAGE_PREFIX = "sis-state:";
    private static final Logger LOG = LogManager.getLogger(SISAuthorisationService.class);
    private static final String RECORD_UPDATE_REQUESTED = "record_update_requested";
    private final StateStorageService stateStorageService;
    private final IdentityAuthorisationService identityAuthorisationService;

    public SISAuthorisationService(
            ConfigurationService configurationService,
            TokenService tokenService,
            StateStorageService stateStorageService,
            CrossBrowserOrchestrationService crossBrowserOrchestrationService,
            JwksCacheService jwksCacheService,
            OrchJwtService orchJwtService,
            NowHelper.NowClock nowClock) {
        this(
                stateStorageService,
                new IdentityAuthorisationService(
                        configurationService,
                        tokenService,
                        stateStorageService,
                        crossBrowserOrchestrationService,
                        orchJwtService,
                        nowClock,
                        new AuditService(configurationService),
                        new Metrics(configurationService),
                        new IdentityAuthConfiguration(
                                STATE_STORAGE_PREFIX,
                                configurationService.getSISAuthorisationClientId(),
                                configurationService.getSISAudience(),
                                configurationService.getSISAuthorisationURI(),
                                configurationService.getSISAuthorisationCallbackURI().toString(),
                                configurationService.getSISTokenSigningKeyAlias(),
                                jwksCacheService::getOrGenerateSISJwksCacheItem,
                                null,
                                "SISHandoff")));
    }

    public SISAuthorisationService(
            StateStorageService stateStorageService,
            IdentityAuthorisationService identityAuthorisationService) {
        this.stateStorageService = stateStorageService;
        this.identityAuthorisationService = identityAuthorisationService;
    }

    public APIGatewayProxyResponseEvent sendRequest(
            AuthenticationRequest authRequest,
            UserInfo userInfo,
            String rpClientID,
            String sessionId,
            String clientSessionId,
            Boolean reproveIdentity,
            List<String> levelsOfConfidence,
            String ipAddress,
            String persistentSessionId,
            String landingPageUrl) {
        return identityAuthorisationService.sendRequest(
                authRequest,
                userInfo,
                rpClientID,
                sessionId,
                clientSessionId,
                reproveIdentity,
                levelsOfConfidence,
                ipAddress,
                persistentSessionId,
                landingPageUrl);
    }

    public Optional<SISCallbackValidationError> validateResponse(
            Map<String, String> queryParams, String sessionId) {
        if (queryParams == null || queryParams.isEmpty()) {
            LOG.warn("No Query parameters in SIS Authorisation response");
            return Optional.of(
                    new SISCallbackValidationError(
                            OAuth2Error.INVALID_REQUEST_CODE, "No query parameters present"));
        }
        if (queryParams.containsKey("error")) {
            if (ACCESS_DENIED_CODE.equals(queryParams.get("error"))) {
                if (RECORD_UPDATE_REQUESTED.equals(queryParams.get("error_description"))) {
                    LOG.info("User requested to update their details");
                    return Optional.of(
                            new SISCallbackValidationError(
                                    queryParams.get("error"),
                                    queryParams.get("error_description"),
                                    true,
                                    true));
                }

                LOG.info("User could not be verified by SIS, routing to IPV");
                return Optional.of(
                        new SISCallbackValidationError(
                                queryParams.get("error"),
                                queryParams.get("error_description"),
                                true,
                                false));
            } else {
                LOG.warn("Error response found in IPV Authorisation response");
                return Optional.of(
                        new SISCallbackValidationError(
                                queryParams.get("error"), queryParams.get("error_description")));
            }
        }
        if (!queryParams.containsKey("state") || queryParams.get("state").isEmpty()) {
            LOG.warn("No state param in IPV Authorisation response");
            return Optional.of(
                    new SISCallbackValidationError(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "No state param present in Authorisation response"));
        }
        if (!isStateValid(sessionId, queryParams.get("state"))) {
            return Optional.of(
                    new SISCallbackValidationError(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "Invalid state param present in Authorisation response"));
        }
        if (!queryParams.containsKey("code") || queryParams.get("code").isEmpty()) {
            LOG.warn("No code param in SIS Authorisation response");
            return Optional.of(
                    new SISCallbackValidationError(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "No code param present in Authorisation response"));
        }
        return Optional.empty();
    }

    private boolean isStateValid(String sessionId, String responseState) {
        var valueFromDynamo =
                stateStorageService
                        .getState(STATE_STORAGE_PREFIX + sessionId)
                        .map(StateItem::getState);
        if (valueFromDynamo.isEmpty()) {
            LOG.info("No state found in Dynamo");
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
