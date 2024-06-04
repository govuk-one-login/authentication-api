package uk.gov.di.orchestration.shared.services;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ErrorObject;
import org.apache.http.client.utils.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.entity.AccountIntervention;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.domain.LogoutAuditableEvent.LOG_OUT_SUCCESS;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.IpAddressHelper.extractIpAddress;
import static uk.gov.di.orchestration.shared.helpers.PersistentIdHelper.extractPersistentIdFromCookieHeader;
import static uk.gov.di.orchestration.shared.services.AuditService.MetadataPair.pair;

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
            String clientId,
            AccountIntervention intervention) {

        var auditUser =
                TxmaAuditUser.user()
                        .withIpAddress(extractIpAddress(input))
                        .withPersistentSessionId(
                                extractPersistentIdFromCookieHeader(input.getHeaders()))
                        .withSessionId(session.getSessionId())
                        .withGovukSigninJourneyId(
                                extractClientSessionIdFromCookieHeaders(input.getHeaders())
                                        .orElse(null))
                        .withUserId(session.getInternalCommonSubjectIdentifier());

        destroySessions(session);
        return generateAccountInterventionLogoutResponse(auditUser, clientId, intervention);
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
                                            configurationService.getInternalSectorURI()));
            LOG.info("Deleting Client Session");
            clientSessionService.deleteStoredClientSession(clientSessionId);
        }
        LOG.info("Deleting Session");
        sessionService.deleteSessionFromRedis(session.getSessionId());
    }

    public APIGatewayProxyResponseEvent generateErrorLogoutResponse(
            Optional<String> state,
            ErrorObject errorObject,
            TxmaAuditUser auditUser,
            Optional<String> clientId) {
        LOG.info(
                "Generating Logout Error Response with code: {} and description: {}",
                errorObject.getCode(),
                errorObject.getDescription());
        return generateLogoutResponse(
                configurationService.getDefaultLogoutURI(),
                state,
                Optional.of(errorObject),
                auditUser,
                clientId);
    }

    public APIGatewayProxyResponseEvent generateDefaultLogoutResponse(
            Optional<String> state, TxmaAuditUser auditUser, Optional<String> clientId) {
        return generateDefaultLogoutResponse(state, auditUser, clientId, Optional.empty());
    }

    public APIGatewayProxyResponseEvent generateDefaultLogoutResponse(
            Optional<String> state,
            TxmaAuditUser auditUser,
            Optional<String> clientId,
            Optional<String> rpPairwiseId) {
        LOG.info("Generating default Logout Response");
        if (auditUser.sessionId() != null) {
            cloudwatchMetricsService.incrementLogout(clientId);
        }
        return generateLogoutResponse(
                configurationService.getDefaultLogoutURI(),
                state,
                Optional.empty(),
                auditUser,
                clientId,
                rpPairwiseId);
    }

    public APIGatewayProxyResponseEvent generateLogoutResponse(
            URI logoutUri,
            Optional<String> state,
            Optional<ErrorObject> errorObject,
            TxmaAuditUser auditUser,
            Optional<String> clientId) {
        return generateLogoutResponse(
                logoutUri, state, errorObject, auditUser, clientId, Optional.empty());
    }

    public APIGatewayProxyResponseEvent generateLogoutResponse(
            URI logoutUri,
            Optional<String> state,
            Optional<ErrorObject> errorObject,
            TxmaAuditUser auditUser,
            Optional<String> clientId,
            Optional<String> rpPairwiseId) {
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

        sendAuditEvent(auditUser, clientId, rpPairwiseId);
        return generateApiGatewayProxyResponse(
                302, "", Map.of(ResponseHeaders.LOCATION, uri.toString()), null);
    }

    private APIGatewayProxyResponseEvent generateAccountInterventionLogoutResponse(
            TxmaAuditUser auditUser, String clientId, AccountIntervention intervention) {
        URI redirectURI;
        if (intervention.getBlocked()) {
            redirectURI = configurationService.getAccountStatusBlockedURI();
            LOG.info("Generating Account Intervention blocked logout response");
        } else if (intervention.getSuspended()) {
            redirectURI = configurationService.getAccountStatusSuspendedURI();
            LOG.info("Generating Account Intervention suspended logout response");
        } else {
            throw new RuntimeException("Account status must be blocked or suspended");
        }

        cloudwatchMetricsService.incrementLogout(Optional.of(clientId), Optional.of(intervention));
        return generateLogoutResponse(
                redirectURI, Optional.empty(), Optional.empty(), auditUser, Optional.of(clientId));
    }

    private void sendAuditEvent(
            TxmaAuditUser auditUser, Optional<String> clientId, Optional<String> rpPairwiseId) {
        String auditClientId = clientId.orElse(AuditService.UNKNOWN);
        var metadata =
                rpPairwiseId
                        .map(i -> new AuditService.MetadataPair[] {pair("rpPairwiseId", i)})
                        .orElse(new AuditService.MetadataPair[] {});
        auditService.submitAuditEvent(LOG_OUT_SUCCESS, auditClientId, auditUser, metadata);
    }

    private Optional<String> extractClientSessionIdFromCookieHeaders(Map<String, String> headers) {
        var sessionCookieIds = new CookieHelper().parseSessionCookie(headers);
        return sessionCookieIds.map(CookieHelper.SessionCookieIds::getClientSessionId);
    }
}
