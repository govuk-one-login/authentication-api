package uk.gov.di.authentication.shared.state.conditions;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.state.Condition;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.List;
import java.util.Optional;

import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;

public class ClientDoesNotRequireMfa implements Condition<UserContext> {

    private static final Logger LOG = LoggerFactory.getLogger(ClientDoesNotRequireMfa.class);

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

        List<String> vtr = authRequest.getCustomParameter("vtr");
        VectorOfTrust vectorOfTrust = VectorOfTrust.parseFromAuthRequestAttribute(vtr);
        if (vectorOfTrust.getCredentialTrustLevel().equals(LOW_LEVEL)) {
            return true;
        } else {
            return false;
        }
    }

    public static ClientDoesNotRequireMfa clientDoesNotRequireMfa() {
        return new ClientDoesNotRequireMfa();
    }
}
