package uk.gov.di.authentication.shared.state.conditions;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.state.Condition;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.List;
import java.util.Optional;

public class ConsentNotGiven implements Condition<UserContext> {

    private static final Logger LOG = LoggerFactory.getLogger(ConsentNotGiven.class);

    @Override
    public boolean isMet(Optional<UserContext> context) {
        AuthenticationRequest authRequest =
                context.map(UserContext::getClientSession)
                        .map(ClientSession::getAuthRequestParams)
                        .map(
                                t -> {
                                    try {
                                        return AuthenticationRequest.parse(t);
                                    } catch (ParseException e) {
                                        LOG.error("Unable to parse AuthRequest", e);
                                        throw new RuntimeException(e);
                                    }
                                })
                        .orElseThrow();

        List<String> authRequestVtr = authRequest.getCustomParameter("vtr");

        String clientID =
                context.flatMap(UserContext::getClient)
                        .map(ClientRegistry::getClientID)
                        .orElseThrow();

        ClientConsent clientConsent =
                context.flatMap(UserContext::getUserProfile)
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

    public static ConsentNotGiven userHasNotGivenConsent() {
        return new ConsentNotGiven();
    }
}
