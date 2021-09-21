package uk.gov.di.authentication.shared.state.conditions;

import uk.gov.di.authentication.shared.state.Condition;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

public class TermsAndConditionsVersionNotAccepted implements Condition<UserContext> {

    private final String latestVersion;

    public TermsAndConditionsVersionNotAccepted(String latestVersion) {
        this.latestVersion = latestVersion;
    }

    @Override
    public boolean isMet(Optional<UserContext> context) {
        if (latestVersion == null) return false;
        return context.map(
                        c ->
                                c.getUserProfile()
                                        .map(
                                                u ->
                                                        !latestVersion.equals(
                                                                u.getTermsAndConditions()
                                                                        .getVersion()))
                                        .orElseThrow())
                .orElseThrow();
    }

    public static TermsAndConditionsVersionNotAccepted userHasNotAcceptedTermsAndConditionsVersion(
            String version) {
        return new TermsAndConditionsVersionNotAccepted(version);
    }
}
