package uk.gov.di.authentication.shared.state.conditions;

import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.state.Condition;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

public class ClientIsAnInternalService implements Condition<UserContext> {

    @Override
    public boolean isMet(Optional<UserContext> context) {
        return context.flatMap(UserContext::getClient)
                .map(ClientRegistry::isInternalService)
                .orElse(false);
    }

    public static ClientIsAnInternalService clientIsAnInternalService() {
        return new ClientIsAnInternalService();
    }
}
