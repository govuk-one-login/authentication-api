package uk.gov.di.orchestration.shared.services;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ErrorObject;
import org.apache.http.client.utils.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.entity.AccountIntervention;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.entity.UserProfile;
import uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper;
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
    private final DynamoService dynamoService;

    public LogoutService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.sessionService = new SessionService(configurationService);
        this.dynamoClientService = new DynamoClientService(configurationService);
        this.clientSessionService = new ClientSessionService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
        this.backChannelLogoutService = new BackChannelLogoutService(configurationService);
        this.dynamoService = new DynamoService(configurationService);
    }

    public LogoutService(
            ConfigurationService configurationService,
            SessionService sessionService,
            DynamoClientService dynamoClientService,
            ClientSessionService clientSessionService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService,
            BackChannelLogoutService backChannelLogoutService,
            DynamoService dynamoService) {
        this.configurationService = configurationService;
        this.sessionService = sessionService;
        this.dynamoClientService = dynamoClientService;
        this.clientSessionService = clientSessionService;
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.backChannelLogoutService = backChannelLogoutService;
        this.dynamoService = dynamoService;
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

    public APIGatewayProxyResponseEvent generateLogoutResponse(
            URI logoutUri,
            Optional<String> state,
            Optional<ErrorObject> errorObject,
            TxmaAuditUser auditUser,
            Optional<String> clientId) {
        LOG.info("Generating logout response using URI: {}", logoutUri);
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
            throw new RuntimeException("Unable to build URI for logout response");
        }

        sendAuditEvent(clientId, auditUser);
        return generateApiGatewayProxyResponse(
                302, "", Map.of(ResponseHeaders.LOCATION, uri.toString()), null);
    }

    private Optional<String> getRpPairwiseId(String subject, String clientId) {
        try {
            if (subject == null || clientId == null) {
                LOG.warn("User or client ID is null while getting RP pairwise ID for audit event");
                return Optional.empty();
            }
            UserProfile userProfile = dynamoService.getUserProfileFromSubject(subject);
            Optional<ClientRegistry> client = dynamoClientService.getClient(clientId);
            if (client.isEmpty()) {
                LOG.warn("Client not found while getting RP pairwise ID for audit event");
                return Optional.empty();
            }
            return Optional.of(
                    ClientSubjectHelper.getSubject(
                                    userProfile,
                                    client.get(),
                                    dynamoService,
                                    configurationService.getInternalSectorUri())
                            .getValue());
        } catch (Exception e) {
            LOG.warn("Exception caught while getting RP pairwise ID for audit event");
            return Optional.empty();
        }
    }

    private void sendAuditEvent(Optional<String> clientId, TxmaAuditUser auditUser) {
        if (clientId.isPresent()) {
            Optional<String> rpPairwiseId = getRpPairwiseId(auditUser.userId(), clientId.get());
            if (rpPairwiseId.isPresent()) {
                auditService.submitAuditEvent(
                        LOG_OUT_SUCCESS,
                        clientId.orElse(AuditService.UNKNOWN),
                        auditUser,
                        pair("rpPairwiseId", rpPairwiseId.get()));
            } else {
                auditService.submitAuditEvent(
                        LOG_OUT_SUCCESS, clientId.orElse(AuditService.UNKNOWN), auditUser);
            }
        } else {
            auditService.submitAuditEvent(
                    LOG_OUT_SUCCESS, clientId.orElse(AuditService.UNKNOWN), auditUser);
        }
    }

    private Optional<String> extractClientSessionIdFromCookieHeaders(Map<String, String> headers) {
        var sessionCookieIds = new CookieHelper().parseSessionCookie(headers);
        return sessionCookieIds.map(CookieHelper.SessionCookieIds::getClientSessionId);
    }
}
