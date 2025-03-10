package uk.gov.di.orchestration.shared.utils;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;

import java.util.Objects;
import java.util.Optional;

public class ClientSessionMigrationUtils {
    private static final Logger LOG = LogManager.getLogger(ClientSessionMigrationUtils.class);

    private ClientSessionMigrationUtils() {}

    public static void logIfClientSessionsAreNotEqual(
            ClientSession clientSession, OrchClientSessionItem orchClientSession) {
        if (!areClientSessionsEqual(clientSession, orchClientSession)) {
            LOG.warn("Client sessions are not equal");
        }
    }

    public static boolean areClientSessionsEqual(
            ClientSession clientSession, OrchClientSessionItem orchClientSession) {
        if (clientSession == null && orchClientSession != null) {
            LOG.warn("Redis client session is null but orch client session is not");
            return false;
        }
        if (clientSession != null && orchClientSession == null) {
            LOG.warn("Orch client session is null but redis client session is not");
            return false;
        }
        if (clientSession == null) {
            LOG.warn("Client sessions are both null");
            return true;
        }
        var equal = true;
        if (!Objects.equals(clientSession.getClientName(), orchClientSession.getClientName())) {
            LOG.warn("Client sessions do not have matching clientName");
            equal = false;
        }
        if (!Objects.equals(
                clientSession.getAuthRequestParams(), orchClientSession.getAuthRequestParams())) {
            LOG.warn("Client sessions do not have matching authRequestParams");
            equal = false;
        }
        var clientSessionDocAppSubjectId =
                Optional.ofNullable(clientSession.getDocAppSubjectId())
                        .map(Subject::getValue)
                        .orElse(null);
        if (!Objects.equals(clientSessionDocAppSubjectId, orchClientSession.getDocAppSubjectId())) {
            LOG.warn("Client sessions do not have matching docAppSubjectId");
            equal = false;
        }
        if (!Objects.equals(clientSession.getCreationDate(), orchClientSession.getCreationDate())) {
            LOG.warn("Client sessions do not have matching creationDate");
            equal = false;
        }
        if (!Objects.equals(clientSession.getVtrList(), orchClientSession.getVtrList())) {
            LOG.warn("Client sessions do not have matching vtrList");
            equal = false;
        }
        if (!Objects.equals(clientSession.getIdTokenHint(), orchClientSession.getIdTokenHint())) {
            LOG.warn("Client sessions do not have matching idTokenHint");
            equal = false;
        }
        if (!Objects.equals(clientSession.getRpPairwiseId(), orchClientSession.getRpPairwiseId())) {
            LOG.warn("Client sessions do not have matching rpPairwiseId");
            equal = false;
        }
        return equal;
    }
}
