package uk.gov.di.authentication.shared.state.conditions;

import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.state.Condition;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;

public class ClientDoesNotRequireMfa implements Condition<UserContext> {
    @Override
    public boolean isMet(Optional<UserContext> context) {
        return context.flatMap(UserContext::getClient)
                .map(ClientRegistry::calculateEffectiveVectorOfTrust)
                .map(VectorOfTrust::getCredentialTrustLevel)
                .map(LOW_LEVEL::equals)
                .orElse(false);
    }

    public static ClientDoesNotRequireMfa clientDoesNotRequireMfa() {
        return new ClientDoesNotRequireMfa();
    }
}
