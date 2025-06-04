package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.DestroySessionsRequest;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;

import java.util.List;

public class GlobalLogoutService {

    private static final Logger LOG = LogManager.getLogger(GlobalLogoutService.class);
    private final OrchSessionService orchSessionService;
    private final LogoutService logoutService;

    public GlobalLogoutService(OrchSessionService orchSessionService, LogoutService logoutService) {
        this.orchSessionService = orchSessionService;
        this.logoutService = logoutService;
    }

    public GlobalLogoutService(ConfigurationService configurationService) {
        this.orchSessionService = new OrchSessionService(configurationService);
        this.logoutService = new LogoutService(configurationService);
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
        destroySessionRequests.forEach(logoutService::destroySessions);
    }
}
