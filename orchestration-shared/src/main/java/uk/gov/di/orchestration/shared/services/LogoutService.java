package uk.gov.di.orchestration.shared.services;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ErrorObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.api.AuthFrontend;
import uk.gov.di.orchestration.shared.entity.AccountIntervention;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;

import java.net.URI;
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
    private final AuthFrontend authFrontend;
    private static final String STATE_PARAMETER_KEY = "state";

    public LogoutService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.sessionService = new SessionService(configurationService);
        this.dynamoClientService = new DynamoClientService(configurationService);
        this.clientSessionService = new ClientSessionService(configurationService);
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
        this.backChannelLogoutService = new BackChannelLogoutService(configurationService);
        this.authFrontend = new AuthFrontend(configurationService);
    }

    public LogoutService(ConfigurationService configurationService, RedisConnectionService redis) {
        this.configurationService = configurationService;
        this.sessionService = new SessionService(configurationService, redis);
        this.dynamoClientService = new DynamoClientService(configurationService);
        this.clientSessionService = new ClientSessionService(configurationService, redis);
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService();
        this.backChannelLogoutService = new BackChannelLogoutService(configurationService);
        this.authFrontend = new AuthFrontend(configurationService);
    }

    public LogoutService(
            ConfigurationService configurationService,
            SessionService sessionService,
            DynamoClientService dynamoClientService,
            ClientSessionService clientSessionService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService,
            BackChannelLogoutService backChannelLogoutService,
            AuthFrontend authFrontend) {
        this.configurationService = configurationService;
        this.sessionService = sessionService;
        this.dynamoClientService = dynamoClientService;
        this.clientSessionService = clientSessionService;
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.backChannelLogoutService = backChannelLogoutService;
        this.authFrontend = authFrontend;
    }

    private APIGatewayProxyResponseEvent generateLogoutResponse(
            URI logoutUri,
            TxmaAuditUser auditUser,
            Optional<String> clientId,
            Optional<String> rpPairwiseId) {
        LOG.info(
                "Generating logout response using URI: {}",
                logoutUri.getHost() + logoutUri.getPath());
        sendAuditEvent(auditUser, clientId, rpPairwiseId);
        return generateApiGatewayProxyResponse(
                302, "", Map.of(ResponseHeaders.LOCATION, logoutUri.toString()), null);
    }

    private void destroySessions(Session session) {
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

    public APIGatewayProxyResponseEvent handleLogout(
            Optional<Session> session,
            Optional<ErrorObject> errorObject,
            Optional<URI> redirectURI,
            Optional<String> state,
            TxmaAuditUser auditUser,
            Optional<String> clientId,
            Optional<String> rpPairwiseId) {

        session.ifPresent(
                s -> {
                    destroySessions(s);
                    cloudwatchMetricsService.incrementLogout(clientId);
                });

        URI logoutUri;
        if (errorObject.isPresent()) {
            logoutUri = authFrontend.errorLogoutURI(errorObject.get());
            LOG.info(
                    "Logout request contains an error object. Generating logout response error redirect URI: \"{}\".",
                    logoutUri);
        } else if (redirectURI.isEmpty()) {
            logoutUri = authFrontend.defaultLogoutURI();
            LOG.info(
                    "Logout request is missing a valid redirect URI. Generating logout response with default redirect URI: \"{}\".",
                    logoutUri);
        } else {
            logoutUri = redirectURI.get();
            LOG.info(
                    "Logout request contains a valid redirect URI and no error object. Generating logout response custom redirect URI: \"{}\".",
                    logoutUri);
        }

        var uri =
                state.map(s -> buildURI(logoutUri, Map.of(STATE_PARAMETER_KEY, s)))
                        .orElse(logoutUri);

        return generateLogoutResponse(uri, auditUser, clientId, rpPairwiseId);
    }

    public APIGatewayProxyResponseEvent handleReauthenticationFailureLogout(
            Session session,
            APIGatewayProxyRequestEvent input,
            String clientId,
            URI errorRedirectUri) {
        var auditUser = createAuditUser(input, session);
        destroySessions(session);
        cloudwatchMetricsService.incrementLogout(Optional.of(clientId));
        return generateLogoutResponse(
                errorRedirectUri, auditUser, Optional.of(clientId), Optional.empty());
    }

    public APIGatewayProxyResponseEvent handleAccountInterventionLogout(
            Session session,
            APIGatewayProxyRequestEvent input,
            String clientId,
            AccountIntervention intervention) {

        var auditUser = createAuditUser(input, session);

        destroySessions(session);
        cloudwatchMetricsService.incrementLogout(Optional.of(clientId), Optional.of(intervention));

        URI redirectURI;
        if (intervention.getBlocked()) {
            redirectURI = authFrontend.accountBlockedURI();
            LOG.info("Generating Account Intervention blocked logout response");
        } else if (intervention.getSuspended()) {
            redirectURI = authFrontend.accountSuspendedURI();
            LOG.info("Generating Account Intervention suspended logout response");
        } else {
            throw new RuntimeException("Account status must be blocked or suspended");
        }

        return generateLogoutResponse(
                redirectURI, auditUser, Optional.of(clientId), Optional.empty());
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

    private TxmaAuditUser createAuditUser(APIGatewayProxyRequestEvent input, Session session) {
        return TxmaAuditUser.user()
                .withIpAddress(extractIpAddress(input))
                .withPersistentSessionId(extractPersistentIdFromCookieHeader(input.getHeaders()))
                .withSessionId(session.getSessionId())
                .withGovukSigninJourneyId(
                        extractClientSessionIdFromCookieHeaders(input.getHeaders()).orElse(null))
                .withUserId(session.getInternalCommonSubjectIdentifier());
    }
}
