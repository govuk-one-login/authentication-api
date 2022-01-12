package uk.gov.di.authentication.shared.state.conditions;

import uk.gov.di.authentication.shared.state.Condition;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

public class ConsentIsNotRequired implements Condition<UserContext> {

    @Override
    public boolean isMet(Optional<UserContext> context) {
        return context.flatMap(UserContext::getClient)
                .map(t -> !t.isConsentRequired())
                .orElse(false);
    }

    public static ConsentIsNotRequired consentIsNotRequired() {
        return new ConsentIsNotRequired();
    }
}
