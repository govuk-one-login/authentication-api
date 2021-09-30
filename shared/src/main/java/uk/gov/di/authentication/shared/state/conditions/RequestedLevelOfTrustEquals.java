package uk.gov.di.authentication.shared.state.conditions;

import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.state.Condition;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;

public class RequestedLevelOfTrustEquals implements Condition<UserContext> {

    private final CredentialTrustLevel requiredLevel;

    public RequestedLevelOfTrustEquals(CredentialTrustLevel requiredLevel) {
        this.requiredLevel = requiredLevel;
    }

    @Override
    public boolean isMet(Optional<UserContext> context) {
        return context.map(UserContext::getClientSession)
                .map(ClientSession::getEffectiveVectorOfTrust)
                .map(VectorOfTrust::getCredentialTrustLevel)
                .map(requiredLevel::equals)
                .orElse(false);
    }

    public static RequestedLevelOfTrustEquals requestedLevelOfTrustIsCm() {
        return new RequestedLevelOfTrustEquals(MEDIUM_LEVEL);
    }
}
