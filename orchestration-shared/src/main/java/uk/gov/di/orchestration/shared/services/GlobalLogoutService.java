package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.DestroySessionsRequest;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;

import java.util.List;
import java.util.Optional;

public class GlobalLogoutService {

    private static final Logger LOG = LogManager.getLogger(GlobalLogoutService.class);
    private final OrchSessionService orchSessionService;
    private final OrchClientSessionService orchClientSessionService;
    private final DynamoClientService dynamoClientService;
    private final BackChannelLogoutService backChannelLogoutService;

    public GlobalLogoutService(ConfigurationService configurationService) {
        this(
                new OrchSessionService(configurationService),
                new OrchClientSessionService(configurationService),
                new DynamoClientService(configurationService),
                new BackChannelLogoutService(configurationService));
    }

    public GlobalLogoutService(
            OrchSessionService orchSessionService,
            OrchClientSessionService orchClientSessionService,
            DynamoClientService dynamoClientService,
            BackChannelLogoutService backChannelLogoutService) {
        this.orchSessionService = orchSessionService;
        this.orchClientSessionService = orchClientSessionService;
        this.dynamoClientService = dynamoClientService;
        this.backChannelLogoutService = backChannelLogoutService;
    }

    public void logoutAllSessions(String internalCommonSubjectId) {
        var allSessions =
                orchSessionService.getSessionsFromInternalCommonSubjectId(internalCommonSubjectId);
        if (allSessions.isEmpty()) {
            LOG.info("No sessions found for internal common subject ID");
            return;
        }
        var destroySessionRequests =
                allSessions.stream()
                        .map(session -> new DestroySessionsRequest(session.getSessionId(), session))
                        .toList();
        LOG.info(
                "Logging out {} sessions and {} client sessions",
                allSessions.size(),
                allSessions.stream()
                        .map(OrchSessionItem::getClientSessions)
                        .mapToLong(List::size)
                        .sum());
        destroySessionRequests.forEach(this::destroySessions);
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
