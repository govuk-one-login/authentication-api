package uk.gov.di.orchestration.shared.utils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.OrchSessionItem;
import uk.gov.di.orchestration.shared.entity.Session;

public class SessionMigrationUtils {

    private SessionMigrationUtils() {}

    private static final Logger LOG = LogManager.getLogger(ClientSessionMigrationUtils.class);

    public static void logIfClientSessionListOnSessionsAreEqual(
            Session session, OrchSessionItem orchSession) {
        try {
            var sharedSessionList = session.getClientSessions();
            var orchSessionList = orchSession.getClientSessions();
            var areEqualDespiteOrdering =
                    sharedSessionList.containsAll(orchSessionList)
                            && orchSessionList.containsAll(sharedSessionList);
            LOG.info(
                    "Are Client Session list equal across both sessions: {}",
                    areEqualDespiteOrdering);

            if (!areEqualDespiteOrdering) {
                LOG.info("Shared session client session list size: {}", sharedSessionList.size());
                LOG.info("Orch session client session list size: {}", orchSessionList.size());
            }
        } catch (Exception e) {
            LOG.warn(
                    "Exception thrown when comparing Client Session lists: {}. Continuing as normal",
                    e.getMessage());
        }
    }
}
