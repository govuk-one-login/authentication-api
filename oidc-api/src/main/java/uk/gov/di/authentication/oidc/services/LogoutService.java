package uk.gov.di.authentication.oidc.services;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ErrorObject;
import org.apache.http.client.utils.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.domain.OidcAuditableEvent;
import uk.gov.di.orchestration.shared.entity.AccountInterventionStatus;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.helpers.ConstructUriHelper;
import uk.gov.di.orchestration.shared.helpers.IpAddressHelper;
import uk.gov.di.orchestration.shared.helpers.PersistentIdHelper;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.ClientSessionService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.SessionService;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class LogoutService {

    private static final Logger LOG = LogManager.getLogger(LogoutService.class);

    private final ConfigurationService configurationService;
    private final SessionService sessionService;
    private final DynamoClientService dynamoClientService;
    private final ClientSessionService clientSessionService;
    private final AuditService auditService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final BackChannelLogoutService backChannelLogoutService;

    public LogoutService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.sessionService = new SessionService(configurationService);
        this.dynamoClientService = new DynamoClientService(configurationService);
        this.clientSessionService = new ClientSessionService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
        this.backChannelLogoutService = new BackChannelLogoutService(configurationService);
    }

    public LogoutService(
            ConfigurationService configurationService,
            SessionService sessionService,
            DynamoClientService dynamoClientService,
            ClientSessionService clientSessionService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService,
            BackChannelLogoutService backChannelLogoutService) {
        this.configurationService = configurationService;
        this.sessionService = sessionService;
        this.dynamoClientService = dynamoClientService;
        this.clientSessionService = clientSessionService;
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.backChannelLogoutService = backChannelLogoutService;
    }

    public APIGatewayProxyResponseEvent handleAccountInterventionLogout(
            Session session,
            APIGatewayProxyRequestEvent input,
            Optional<String> clientId,
            Optional<String> sessionId,
            AccountInterventionStatus accountStatus) {
        destroySessions(session);
        return generateAccountInterventionLogoutResponse(input, clientId, sessionId, accountStatus);
    }

    public void destroySessions(Session session) {
        for (String clientSessionId : session.getClientSessions()) {
            clientSessionService
                    .getClientSession(clientSessionId)
                    .flatMap(
                            t ->
                                    t.getAuthRequestParams().get("client_id").stream()
                                            .findFirst()
                                            .flatMap(dynamoClientService::getClient))
                    .ifPresent(
                            clientRegistry ->
                                    backChannelLogoutService.sendLogoutMessage(
                                            clientRegistry,
                                            session.getEmailAddress(),
                                            configurationService.getInternalSectorUri()));
            LOG.info("Deleting Client Session");
            clientSessionService.deleteClientSessionFromRedis(clientSessionId);
        }
        LOG.info("Deleting Session");
        sessionService.deleteSessionFromRedis(session.getSessionId());
    }

    public APIGatewayProxyResponseEvent generateErrorLogoutResponse(
            Optional<String> state,
            ErrorObject errorObject,
            APIGatewayProxyRequestEvent input,
            Optional<String> clientId,
            Optional<String> sessionId) {
        LOG.info(
                "Generating Logout Error Response with code: {} and description: {}",
                errorObject.getCode(),
                errorObject.getDescription());
        return generateLogoutResponse(
                configurationService.getDefaultLogoutURI(),
                state,
                Optional.of(errorObject),
                input,
                clientId,
                sessionId);
    }

    public APIGatewayProxyResponseEvent generateDefaultLogoutResponse(
            Optional<String> state,
            APIGatewayProxyRequestEvent input,
            Optional<String> clientId,
            Optional<String> sessionId) {
        LOG.info("Generating default Logout Response");
        sessionId.ifPresent(t -> cloudwatchMetricsService.incrementLogout(clientId));
        return generateLogoutResponse(
                configurationService.getDefaultLogoutURI(),
                state,
                Optional.empty(),
                input,
                clientId,
                sessionId);
    }

    public APIGatewayProxyResponseEvent generateLogoutResponse(
            URI logoutUri,
            Optional<String> state,
            Optional<ErrorObject> errorObject,
            APIGatewayProxyRequestEvent input,
            Optional<String> clientId,
            Optional<String> sessionId) {
        LOG.info("Generating Logout Response using URI: {}", logoutUri);
        URIBuilder uriBuilder = new URIBuilder(logoutUri);
        state.ifPresent(s -> uriBuilder.addParameter("state", s));
        errorObject.ifPresent(e -> uriBuilder.addParameter("error_code", e.getCode()));
        errorObject.ifPresent(
                e -> uriBuilder.addParameter("error_description", e.getDescription()));
        URI uri;
        try {
            uri = uriBuilder.build();
        } catch (URISyntaxException e) {
            LOG.error("Unable to generate logout response", e);
            throw new RuntimeException("Unable to build URI");
        }
        auditService.submitAuditEvent(
                OidcAuditableEvent.LOG_OUT_SUCCESS,
                AuditService.UNKNOWN,
                sessionId.orElse(AuditService.UNKNOWN),
                clientId.orElse(AuditService.UNKNOWN),
                AuditService.UNKNOWN,
                AuditService.UNKNOWN,
                IpAddressHelper.extractIpAddress(input),
                AuditService.UNKNOWN,
                PersistentIdHelper.extractPersistentIdFromCookieHeader(input.getHeaders()));

        return generateApiGatewayProxyResponse(
                302, "", Map.of(ResponseHeaders.LOCATION, uri.toString()), null);
    }

    private APIGatewayProxyResponseEvent generateAccountInterventionLogoutResponse(
            APIGatewayProxyRequestEvent input,
            Optional<String> clientId,
            Optional<String> sessionId,
            AccountInterventionStatus accountStatus) {
        String baseRedirectUrl;
        String redirectPath;
        // Temporarily redirect to auth frontend (in staging and production) instead of orch
        // frontend, while orch frontend is not deployed in these envs.
        String env = configurationService.getEnvironment();
        if (env.equals("staging") || env.equals("production")) {
            baseRedirectUrl = configurationService.getFrontendBaseUrl();
            if (accountStatus.blocked()) {
                redirectPath = "/unavailable-permanent";
                LOG.info("Generating Account Intervention blocked logout response");
            } else if (accountStatus.suspended()) {
                redirectPath = "/unavailable-temporary";
                LOG.info("Generating Account Intervention suspended logout response");
            } else {
                throw new RuntimeException("Account status must be blocked or suspended");
            }
        } else {
            baseRedirectUrl = configurationService.getOidcApiBaseURL().orElseThrow();
            if (accountStatus.blocked()) {
                redirectPath = configurationService.getAccountStatusBlockedURI();
                LOG.info("Generating Account Intervention blocked logout response");
            } else if (accountStatus.suspended()) {
                redirectPath = configurationService.getAccountStatusSuspendedURI();
                LOG.info("Generating Account Intervention suspended logout response");
            } else {
                throw new RuntimeException("Account status must be blocked or suspended");
            }
        }
        sessionId.ifPresent(
                t ->
                        cloudwatchMetricsService.incrementLogout(
                                clientId, Optional.of(accountStatus)));
        return generateLogoutResponse(
                ConstructUriHelper.buildURI(baseRedirectUrl, redirectPath),
                Optional.empty(),
                Optional.empty(),
                input,
                clientId,
                sessionId);
    }
}
