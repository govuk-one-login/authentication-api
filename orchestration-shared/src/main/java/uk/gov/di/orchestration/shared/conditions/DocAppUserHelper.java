package uk.gov.di.orchestration.shared.conditions;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.CustomScopeValue;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.exceptions.RequestObjectException;
import uk.gov.di.orchestration.shared.state.UserContext;

import java.util.List;
import java.util.Map;
import java.util.Optional;

public class DocAppUserHelper {

    private static final Logger LOG = LogManager.getLogger(DocAppUserHelper.class);

    private DocAppUserHelper() {}

    public static boolean isDocCheckingAppUser(UserContext context) {
        var authRequestParams = context.getOrchClientSession().getAuthRequestParams();
        return isDocCheckingAppUser(authRequestParams, context.getClient());
    }

    public static boolean isDocCheckingAppUser(
            Map<String, List<String>> authRequestParams, Optional<ClientRegistry> clientRegistry) {
        if (!authRequestParams.containsKey("request")) {
            LOG.info("No request object in auth request");
            return false;
        }
        if (!hasDocCheckingScope(authRequestParams)) {
            LOG.info("No doc app scope in auth request");
            return false;
        } else {
            return clientRegistry
                    .filter(client -> client.getClientType().equals(ClientType.APP.getValue()))
                    .isPresent();
        }
    }

    public static boolean isDocCheckingAppUserWithSubjectId(
            OrchClientSessionItem orchClientSession) {
        boolean isDocCheckingUser =
                orchClientSession.getDocAppSubjectId() != null
                        && hasDocCheckingScope(orchClientSession.getAuthRequestParams());
        LOG.info("User is Doc Checking App user: {}", isDocCheckingUser);
        return isDocCheckingUser;
    }

    private static boolean hasDocCheckingScope(Map<String, List<String>> authRequestParams) {
        try {
            var authRequest = AuthenticationRequest.parse(authRequestParams);
            return authRequest.getScope().contains(CustomScopeValue.DOC_CHECKING_APP);
        } catch (ParseException e) {
            LOG.error("Unable to parse auth request", e);
            throw new RequestObjectException("Unable to parse auth request", e);
        }
    }
}
