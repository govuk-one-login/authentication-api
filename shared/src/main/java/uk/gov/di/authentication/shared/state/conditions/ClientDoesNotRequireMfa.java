package uk.gov.di.authentication.shared.state.conditions;

import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.state.Condition;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static uk.gov.di.authentication.shared.entity.AuthenticationValues.LOW_LEVEL;

public class ClientDoesNotRequireMfa implements Condition<UserContext> {
    @Override
    public boolean isMet(Optional<UserContext> context) {
        return context.flatMap(UserContext::getClient)
                .map(ClientRegistry::getVectorsOfTrust)
                .map(LOW_LEVEL.getValue()::equals)
                .orElse(false);
    }

    public static ClientDoesNotRequireMfa clientDoesNotRequireMfa() {
        return new ClientDoesNotRequireMfa();
    }
}
