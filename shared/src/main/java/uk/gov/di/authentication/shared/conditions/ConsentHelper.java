package uk.gov.di.authentication.shared.conditions;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.state.UserContext;

public class ConsentHelper {

    private static final Logger LOG = LogManager.getLogger(ConsentHelper.class);

    private ConsentHelper() {}

    public static boolean userHasNotGivenConsent(UserContext context) {
        if (Boolean.FALSE.equals(
                context.getClient().map(ClientRegistry::isConsentRequired).orElseThrow())) {
            return false;
        }
        AuthenticationRequest authRequest;
        try {
            authRequest =
                    AuthenticationRequest.parse(context.getClientSession().getAuthRequestParams());
        } catch (ParseException e) {
            LOG.error("Unable to parse AuthRequest", e);
            throw new RuntimeException(e);
        }

        String clientID = context.getClient().map(ClientRegistry::getClientID).orElseThrow();

        ClientConsent clientConsent =
                context.getUserProfile()
                        .map(UserProfile::getClientConsent)
                        .flatMap(
                                t ->
                                        t.stream()
                                                .filter(c -> c.getClientId().equals(clientID))
                                                .findFirst())
                        .orElse(null);

        if (clientConsent == null) {
            return true;
        }

        return !clientConsent
                .getClaims()
                .containsAll(
                        ValidScopes.getClaimsForListOfScopes(
                                authRequest.getScope().toStringList()));
    }
}
