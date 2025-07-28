package uk.gov.di.orchestration.shared.services;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.State;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jetbrains.annotations.NotNull;
import uk.gov.di.orchestration.shared.entity.CrossBrowserEntity;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.exceptions.NoSessionException;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_NAME;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.GOVUK_SIGNIN_JOURNEY_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class NoSessionOrchestrationService {

    private static final Logger LOG = LogManager.getLogger(NoSessionOrchestrationService.class);
    private final RedisConnectionService redisConnectionService;
    private final OrchClientSessionService orchClientSessionService;
    private final ConfigurationService configurationService;
    public static final String STATE_STORAGE_PREFIX = "state:";

    public NoSessionOrchestrationService(
            RedisConnectionService redisConnectionService,
            OrchClientSessionService orchClientSessionService,
            ConfigurationService configurationService) {
        this.redisConnectionService = redisConnectionService;
        this.orchClientSessionService = orchClientSessionService;
        this.configurationService = configurationService;
    }

    public NoSessionOrchestrationService(ConfigurationService configurationService) {
        this(
                new RedisConnectionService(configurationService),
                new OrchClientSessionService(configurationService),
                configurationService);
    }

    public NoSessionOrchestrationService(
            ConfigurationService configurationService, RedisConnectionService redis) {
        this(redis, new OrchClientSessionService(configurationService), configurationService);
    }

    public CrossBrowserEntity generateNoSessionOrchestrationEntity(
            Map<String, String> queryStringParameters) throws NoSessionException {
        LOG.info("Attempting to generate error response using state");
        if (isAccessDeniedErrorAndStatePresent(queryStringParameters)) {
            LOG.info("access_denied error and state param are both present");
            var clientSessionId =
                    getClientSessionIdFromState(State.parse(queryStringParameters.get("state")))
                            .orElseThrow(
                                    () ->
                                            new NoSessionException(
                                                    "ClientSessionId could not be found using state param"));
            LOG.info("ClientSessionID found using state");
            attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionId);
            attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, clientSessionId);
            var orchClientSession =
                    orchClientSessionService
                            .getClientSession(clientSessionId)
                            .orElseThrow(
                                    () ->
                                            new NoSessionException(
                                                    "No client session found with given client sessionId"));

            LOG.info("ClientSession found using clientSessionId");

            try {
                attachLogFieldToLogs(CLIENT_NAME, orchClientSession.getClientName());
                attachLogFieldToLogs(CLIENT_ID, clientIdFromClientSession(orchClientSession));
            } catch (Exception e) {
                LOG.warn("Failed to attach client details to logs");
            }

            var errorObject =
                    new ErrorObject(
                            OAuth2Error.ACCESS_DENIED_CODE,
                            "Access denied for security reasons, a new authentication request may be successful");
            LOG.info(
                    "ErrorObject created for session cookie not present. Generating NoSessionEntity in preparation for response to RP");
            return new CrossBrowserEntity(clientSessionId, errorObject, orchClientSession);
        } else {
            LOG.warn(
                    "Session Cookie not present and access_denied or state param missing from error response");
            throw new NoSessionException(
                    "Session Cookie not present and access_denied or state param missing from error response");
        }
    }

    public Optional<CrossBrowserEntity> generateEntityForMismatchInClientSessionId(
            Map<String, String> queryStringParameters, String clientSessionIdFromCookie)
            throws NoSessionException {
        if (!isStatePresentInQueryParams(queryStringParameters)) {
            LOG.warn("No state value in query params");
            throw new NoSessionException("No state provided in the query params");
        }

        var clientSessionIdFromState =
                getClientSessionIdFromState(State.parse(queryStringParameters.get("state")))
                        .orElseThrow(
                                () ->
                                        new NoSessionException(
                                                "Could not find ClientSessionID from state param"));

        attachLogFieldToLogs(CLIENT_SESSION_ID, clientSessionIdFromState);
        attachLogFieldToLogs(GOVUK_SIGNIN_JOURNEY_ID, clientSessionIdFromState);

        if (clientSessionIdFromCookie.equals(clientSessionIdFromState)) {
            LOG.info("No mismatch between state derived and cookie derived client session IDs");
            return Optional.empty();
        }

        LOG.warn(
                "Client session ID from cookie does not match value from state, using state derived value to return error to RP. Cookie: {}, State: {}",
                clientSessionIdFromCookie,
                clientSessionIdFromState);

        var orchClientSession =
                orchClientSessionService
                        .getClientSession(clientSessionIdFromState)
                        .orElseThrow(
                                () ->
                                        new NoSessionException(
                                                "No client session found with given client sessionId"));

        try {
            attachLogFieldToLogs(CLIENT_NAME, orchClientSession.getClientName());
            attachLogFieldToLogs(CLIENT_ID, clientIdFromClientSession(orchClientSession));
        } catch (Exception e) {
            LOG.warn("Failed to attach client details to logs");
        }

        var errorObject =
                new ErrorObject(
                        OAuth2Error.ACCESS_DENIED_CODE,
                        "Access denied for security reasons, a new authentication request may be successful");

        return Optional.of(
                new CrossBrowserEntity(clientSessionIdFromState, errorObject, orchClientSession));
    }

    @NotNull
    private static String clientIdFromClientSession(OrchClientSessionItem clientSession) {
        return clientSession.getAuthRequestParams().get("client_id").stream()
                .findFirst()
                .orElse("unknown");
    }

    public void storeClientSessionIdAgainstState(String clientSessionId, State state) {
        LOG.info("Storing clientSessionId against state");
        redisConnectionService.saveWithExpiry(
                STATE_STORAGE_PREFIX + state.getValue(),
                clientSessionId,
                configurationService.getSessionExpiry());
    }

    private Optional<String> getClientSessionIdFromState(State state) {
        LOG.info("Getting clientSessionId using state");
        return Optional.ofNullable(
                redisConnectionService.getValue(STATE_STORAGE_PREFIX + state.getValue()));
    }

    private boolean isAccessDeniedErrorAndStatePresent(Map<String, String> queryStringParameters) {
        return Objects.nonNull(queryStringParameters)
                && queryStringParameters.containsKey("error")
                && queryStringParameters.get("error").equals(OAuth2Error.ACCESS_DENIED.getCode())
                && queryStringParameters.containsKey("state")
                && Boolean.FALSE.equals(queryStringParameters.get("state").isEmpty());
    }

    private boolean isStatePresentInQueryParams(Map<String, String> queryStringParameters) {
        return Objects.nonNull(queryStringParameters)
                && queryStringParameters.containsKey("state")
                && Boolean.FALSE.equals(queryStringParameters.get("state").isEmpty());
    }
}
