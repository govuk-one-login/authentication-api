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

        var clientSessionDocAppSubjectId =
                Optional.ofNullable(clientSession.getDocAppSubjectId())
                        .map(Subject::getValue)
                        .orElse(null);

        return areFieldsEqual(
                        "clientName",
                        clientSession.getClientName(),
                        orchClientSession.getClientName())
                && areFieldsEqual(
                        "authRequestParams",
                        clientSession.getAuthRequestParams(),
                        orchClientSession.getAuthRequestParams())
                && areFieldsEqual(
                        "docAppSubjectId",
                        clientSessionDocAppSubjectId,
                        orchClientSession.getDocAppSubjectId())
                && areFieldsEqual(
                        "creationDate",
                        clientSession.getCreationDate(),
                        orchClientSession.getCreationDate())
                && areFieldsEqual(
                        "vtrList", clientSession.getVtrList(), orchClientSession.getVtrList())
                && areFieldsEqual(
                        "idTokenHint",
                        clientSession.getIdTokenHint(),
                        orchClientSession.getIdTokenHint())
                && areFieldsEqual(
                        "rpPairwiseId",
                        clientSession.getRpPairwiseId(),
                        orchClientSession.getRpPairwiseId());
    }

    private static <T> boolean areFieldsEqual(
            String fieldName, T clientSessionField, T orchClientSessionField) {
        if (Objects.isNull(clientSessionField) && Objects.nonNull(orchClientSessionField)) {
            LOG.warn(
                    "Client sessions do not have matching {} (clientSession field is null)",
                    fieldName);
            return false;
        }
        if (Objects.nonNull(clientSessionField) && Objects.isNull(orchClientSessionField)) {
            LOG.warn(
                    "Client sessions do not have matching {} (orchClientSession field is null)",
                    fieldName);
            return false;
        }
        if (!Objects.equals(clientSessionField, orchClientSessionField)) {
            LOG.warn(
                    "Client sessions do not have matching {} (both fields are not null)",
                    fieldName);
            return false;
        }
        return true;
    }
}
