package uk.gov.di.authentication.shared.conditions;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.exceptions.RequestObjectException;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.List;
import java.util.Map;

public class DocAppUserHelper {

    private static final Logger LOG = LogManager.getLogger(DocAppUserHelper.class);

    private DocAppUserHelper() {}

    public static boolean isDocCheckingAppUser(UserContext context) {
        var authRequestParams = context.getClientSession().getAuthRequestParams();
        if (!authRequestParams.containsKey("request")) {
            LOG.info("No request object in auth request");
            return false;
        }
        if (!hasDocCheckingScope(authRequestParams)) {
            LOG.info("No doc app scope in auth request");
            return false;
        } else {
            return context.getClient()
                    .filter(t -> t.getClientType().equals(ClientType.APP.getValue()))
                    .isPresent();
        }
    }

    public static boolean isDocCheckingAppUserWithSubjectId(ClientSession clientSession) {
        return clientSession.getDocAppSubjectId() != null
                && hasDocCheckingScope(clientSession.getAuthRequestParams());
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
