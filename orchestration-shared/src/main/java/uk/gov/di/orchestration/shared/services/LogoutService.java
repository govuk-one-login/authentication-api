package uk.gov.di.orchestration.shared.services;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ErrorObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.api.AuthFrontend;
import uk.gov.di.orchestration.shared.entity.AccountIntervention;
import uk.gov.di.orchestration.shared.entity.DestroySessionsRequest;
import uk.gov.di.orchestration.shared.entity.LogoutReason;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.ResponseHeaders;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.helpers.NowHelper.NowClock;

import java.net.URI;
import java.time.Clock;
import java.util.LinkedList;
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

    private final OrchSessionService orchSessionService;
    private final DynamoClientService dynamoClientService;
    private final OrchClientSessionService orchClientSessionService;
    private final AuditService auditService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final BackChannelLogoutService backChannelLogoutService;
    private final AuthFrontend authFrontend;
    private final NowClock nowClock;
    private static final String STATE_PARAMETER_KEY = "state";
    private static final String LOGOUT_REASON = "logoutReason";

    public LogoutService(ConfigurationService configurationService) {
        this(
                new OrchSessionService(configurationService),
                new DynamoClientService(configurationService),
                new OrchClientSessionService(configurationService),
                new AuditService(configurationService),
                new CloudwatchMetricsService(),
                new BackChannelLogoutService(configurationService),
                new AuthFrontend(configurationService),
                new NowClock(Clock.systemUTC()));
    }

    public LogoutService(
            OrchSessionService orchSessionService,
            DynamoClientService dynamoClientService,
            OrchClientSessionService orchClientSessionService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService,
            BackChannelLogoutService backChannelLogoutService,
            AuthFrontend authFrontend,
            NowClock nowClock) {
        this.orchSessionService = orchSessionService;
        this.dynamoClientService = dynamoClientService;
        this.orchClientSessionService = orchClientSessionService;
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.backChannelLogoutService = backChannelLogoutService;
        this.authFrontend = authFrontend;
        this.nowClock = nowClock;
    }

    private APIGatewayProxyResponseEvent generateLogoutResponse(
            URI logoutUri,
            LogoutReason logoutReason,
            TxmaAuditUser auditUser,
            Optional<String> clientId,
            Optional<String> rpPairwiseId) {
        LOG.info(
                "Generating logout response using URI: {}",
                logoutUri.getHost() + logoutUri.getPath());
        sendAuditEvent(auditUser, logoutReason, clientId, rpPairwiseId, Optional.empty());
        return generateApiGatewayProxyResponse(
                302, "", Map.of(ResponseHeaders.LOCATION, logoutUri.toString()), null);
    }

    private void destroySessions(DestroySessionsRequest request) {
        for (String clientSessionId : request.getClientSessions()) {
            var orchClientSessionOpt = orchClientSessionService.getClientSession(clientSessionId);

            sendBackchannelLogoutIfPresent(orchClientSessionOpt);
            LOG.info("Deleting Orch Client session");
            orchClientSessionService.deleteStoredClientSession(clientSessionId);
        }

        LOG.info("Deleting Orch Session");
        orchSessionService.deleteSession(request.getSessionId());
    }

    public APIGatewayProxyResponseEvent handleLogout(
            Optional<DestroySessionsRequest> destroySessionsRequest,
            Optional<ErrorObject> errorObject,
            Optional<URI> redirectURI,
            Optional<String> state,
            TxmaAuditUser auditUser,
            Optional<String> clientId,
            Optional<String> rpPairwiseId) {

        destroySessionsRequest.ifPresent(
                request -> {
                    destroySessions(request);
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

        return generateLogoutResponse(
                uri, LogoutReason.FRONT_CHANNEL, auditUser, clientId, rpPairwiseId);
    }

    public APIGatewayProxyResponseEvent handleReauthenticationFailureLogout(
            DestroySessionsRequest request,
            String internalCommonSubjectId,
            APIGatewayProxyRequestEvent input,
            String clientId,
            URI errorRedirectUri) {
        var auditUser = createAuditUser(input, request.getSessionId(), internalCommonSubjectId);
        destroySessions(request);
        cloudwatchMetricsService.incrementLogout(Optional.of(clientId));
        return generateLogoutResponse(
                errorRedirectUri,
                LogoutReason.REAUTHENTICATION_FAILURE,
                auditUser,
                Optional.of(clientId),
                Optional.empty());
    }

    public APIGatewayProxyResponseEvent handleAccountInterventionLogout(
            DestroySessionsRequest request,
            String internalCommonSubjectId,
            APIGatewayProxyRequestEvent input,
            String clientId,
            AccountIntervention intervention) {

        var auditUser = createAuditUser(input, request.getSessionId(), internalCommonSubjectId);

        destroySessions(request);
        cloudwatchMetricsService.incrementLogout(Optional.of(clientId), Optional.of(intervention));

        URI redirectURI;
        if (intervention.getBlocked()) {
            redirectURI = authFrontend.accountBlockedURI();
            LOG.info("Generating Account Intervention blocked logout response");
        } else if (intervention.getSuspended()) {
            redirectURI = authFrontend.accountSuspendedURI();
            LOG.info("Generating Account Intervention suspended logout response");
        } else {
            LOG.error("Account status must be blocked or suspended");
            throw new RuntimeException("Account status must be blocked or suspended");
        }

        return generateLogoutResponse(
                redirectURI,
                LogoutReason.INTERVENTION,
                auditUser,
                Optional.of(clientId),
                Optional.empty());
    }

    public void handleMaxAgeLogout(
            DestroySessionsRequest request,
            OrchSessionItem previousOrchSession,
            TxmaAuditUser user) {
        destroySessions(request);
        Long sessionAge =
                nowClock.now().toInstant().getEpochSecond() - previousOrchSession.getAuthTime();
        sendAuditEvent(
                user,
                LogoutReason.MAX_AGE_EXPIRY,
                Optional.empty(),
                Optional.empty(),
                Optional.of(sessionAge));
    }

    public APIGatewayProxyResponseEvent handleSessionInvalidationLogout(
            DestroySessionsRequest request,
            String internalCommonSubjectId,
            APIGatewayProxyRequestEvent input,
            String clientId) {
        LOG.info("Handling session invalidation logout");
        destroySessions(request);
        var auditUser = createAuditUser(input, request.getSessionId(), internalCommonSubjectId);
        return generateLogoutResponse(
                // ATO-1796: Create new error page on auth frontend for this scenario
                authFrontend.defaultLogoutURI(),
                LogoutReason.INTERVENTION,
                auditUser,
                Optional.of(clientId),
                Optional.empty());
    }

    private void sendAuditEvent(
            TxmaAuditUser auditUser,
            LogoutReason logoutReason,
            Optional<String> clientId,
            Optional<String> rpPairwiseId,
            Optional<Long> sessionAge) {
        String auditClientId = clientId.orElse(AuditService.UNKNOWN);
        var metadata = new LinkedList<AuditService.MetadataPair>();
        metadata.add(pair(LOGOUT_REASON, logoutReason.getValue()));
        rpPairwiseId.ifPresent(i -> metadata.add(pair("rpPairwiseId", i)));
        sessionAge.ifPresent(age -> metadata.add(pair("sessionAge", age.intValue())));
        auditService.submitAuditEvent(
                LOG_OUT_SUCCESS,
                auditClientId,
                auditUser,
                metadata.toArray(AuditService.MetadataPair[]::new));
    }

    private TxmaAuditUser createAuditUser(
            APIGatewayProxyRequestEvent input, String sessionId, String internalCommonSubjectId) {
        return TxmaAuditUser.user()
                .withIpAddress(extractIpAddress(input))
                .withPersistentSessionId(extractPersistentIdFromCookieHeader(input.getHeaders()))
                .withSessionId(sessionId)
                .withGovukSigninJourneyId(
                        CookieHelper.getClientSessionIdFromRequestHeaders(input.getHeaders())
                                .orElse(null))
                .withUserId(internalCommonSubjectId);
    }

    private void sendBackchannelLogoutIfPresent(
            Optional<OrchClientSessionItem> orchClientSessionItemOpt) {
        if (orchClientSessionItemOpt.isEmpty()) return;
        var orchClientSessionItem = orchClientSessionItemOpt.get();

        var clientOpt =
                orchClientSessionItem.getAuthRequestParams().get("client_id").stream()
                        .findFirst()
                        .flatMap(dynamoClientService::getClient);
        if (clientOpt.isEmpty()) return;
        var client = clientOpt.get();

        var pairwiseIdOpt =
                Optional.ofNullable(
                        orchClientSessionItem.getCorrectPairwiseIdGivenSubjectType(
                                client.getSubjectType()));
        if (pairwiseIdOpt.isEmpty()) return;
        var pairwiseId = pairwiseIdOpt.get();

        backChannelLogoutService.sendLogoutMessage(client, pairwiseId);
    }
}
