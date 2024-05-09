package uk.gov.di.orchestration.shared.services;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ErrorObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.api.FrontEndPages;
import uk.gov.di.orchestration.shared.entity.AccountIntervention;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.entity.UserProfile;
import uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.domain.LogoutAuditableEvent.LOG_OUT_SUCCESS;
import static uk.gov.di.orchestration.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;
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
    private final FrontEndPages frontEndPages;
    private static final String STATE_PARAMETER_KEY = "state";

    public LogoutService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.sessionService = new SessionService(configurationService);
        this.dynamoClientService = new DynamoClientService(configurationService);
        this.clientSessionService = new ClientSessionService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
        this.backChannelLogoutService = new BackChannelLogoutService(configurationService);
        this.dynamoService = new DynamoService(configurationService);
        this.frontEndPages = new FrontEndPages(configurationService);
    }

    public LogoutService(
            ConfigurationService configurationService,
            SessionService sessionService,
            DynamoClientService dynamoClientService,
            ClientSessionService clientSessionService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService,
            BackChannelLogoutService backChannelLogoutService,
            DynamoService dynamoService,
            FrontEndPages frontEndPages) {
        this.configurationService = configurationService;
        this.sessionService = sessionService;
        this.dynamoClientService = dynamoClientService;
        this.clientSessionService = clientSessionService;
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.backChannelLogoutService = backChannelLogoutService;
        this.dynamoService = dynamoService;
        this.frontEndPages = frontEndPages;
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
                                            configurationService
                                                    .getInternalSectorURI()
                                                    .toString()));
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
                frontEndPages.logoutURI(Optional.of(errorObject)),
                state,
                auditUser,
                clientId);
    }

    public APIGatewayProxyResponseEvent generateDefaultLogoutResponse(
            Optional<String> state, TxmaAuditUser auditUser, Optional<String> clientId) {
        LOG.info("Generating default Logout Response");
        if (auditUser.sessionId() != null) {
            cloudwatchMetricsService.incrementLogout(clientId);
        }
        return generateLogoutResponse(
                frontEndPages.logoutURI(Optional.empty()),
                state,
                auditUser,
                clientId);
    }

    public APIGatewayProxyResponseEvent generateCustomLogoutResponse(
            URI logoutUri,
            Optional<String> state,
            TxmaAuditUser auditUser,
            Optional<String> clientId) {
        LOG.info("Generating Logout Response using URI: {}", logoutUri);
        return generateLogoutResponse(logoutUri, state, auditUser, clientId);
    }

    private APIGatewayProxyResponseEvent generateLogoutResponse(
            URI logoutUri,
            Optional<String> state,
            TxmaAuditUser auditUser,
            Optional<String> clientId) {
        var queryParameters = new HashMap<String, String>();
        state.ifPresent(s -> queryParameters.put(STATE_PARAMETER_KEY, s));
        logoutUri = buildURI(logoutUri, queryParameters);

        sendAuditEvent(clientId, auditUser);
        return generateApiGatewayProxyResponse(
                302, "", Map.of(ResponseHeaders.LOCATION, logoutUri.toString()), null);
    }

    private APIGatewayProxyResponseEvent generateAccountInterventionLogoutResponse(
            TxmaAuditUser auditUser, String clientId, AccountIntervention intervention) {
        URI redirectURI;
        if (intervention.getBlocked()) {
            redirectURI = frontEndPages.accountBlockedURI();
            LOG.info("Generating Account Intervention blocked logout response");
        } else if (intervention.getSuspended()) {
            redirectURI = frontEndPages.accountSuspendedURI();
            LOG.info("Generating Account Intervention suspended logout response");
        } else {
            throw new RuntimeException("Account status must be blocked or suspended");
        }

        cloudwatchMetricsService.incrementLogout(Optional.of(clientId), Optional.of(intervention));
            return generateCustomLogoutResponse(
                    redirectURI,
                    Optional.empty(),
                    auditUser,
                    Optional.of(clientId));
    }

    public Optional<String> getRpPairwiseId(String subject, String clientId) {
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
                                    configurationService.getInternalSectorURI().toString())
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
}
