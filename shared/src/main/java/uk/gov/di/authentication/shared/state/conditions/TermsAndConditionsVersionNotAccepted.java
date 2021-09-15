package uk.gov.di.authentication.shared.state.conditions;

import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.state.Condition;

import java.util.Optional;

public class TermsAndConditionsVersionNotAccepted implements Condition<UserProfile> {

    private final String latestVersion;

    public TermsAndConditionsVersionNotAccepted(String latestVersion) {
        this.latestVersion = latestVersion;
    }

    @Override
    public boolean isMet(Optional<UserProfile> context) {
        if (latestVersion == null) return false;
        return context.map(u -> !latestVersion.equals(u.getTermsAndConditions().getVersion()))
                .orElse(true);
    }

    public static TermsAndConditionsVersionNotAccepted userHasNotAcceptedTermsAndConditionsVersion(
            String version) {
        return new TermsAndConditionsVersionNotAccepted(version);
    }
}
