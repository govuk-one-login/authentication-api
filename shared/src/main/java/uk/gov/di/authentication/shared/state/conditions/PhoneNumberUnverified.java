package uk.gov.di.authentication.shared.state.conditions;

import uk.gov.di.authentication.shared.state.Condition;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

public class PhoneNumberUnverified implements Condition<UserContext> {

    @Override
    public boolean isMet(Optional<UserContext> context) {
        return context.flatMap(UserContext::getUserProfile)
                .map(t -> !t.isPhoneNumberVerified())
                .orElse(false);
    }

    public static PhoneNumberUnverified phoneNumberUnverified() {
        return new PhoneNumberUnverified();
    }
}
