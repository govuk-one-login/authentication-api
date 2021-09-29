package uk.gov.di.authentication.shared.state.conditions;

import uk.gov.di.authentication.shared.state.Condition;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static java.util.Objects.nonNull;

public class CredentialTrustUpliftRequired implements Condition<UserContext> {
    @Override
    public boolean isMet(Optional<UserContext> context) {

        return context.filter(
                        c ->
                                nonNull(c.getSession().getCurrentCredentialStrength())
                                        && nonNull(c.getClientSession()))
                .map(
                        c ->
                                c.getSession()
                                                .getCurrentCredentialStrength()
                                                .compareTo(
                                                        c.getClientSession()
                                                                .getEffectiveVectorOfTrust()
                                                                .getCredentialTrustLevel())
                                        < 0)
                .orElse(false);
    }

    public static CredentialTrustUpliftRequired upliftRequired() {
        return new CredentialTrustUpliftRequired();
    }
}
