package uk.gov.di.authentication.shared.state.conditions;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserProfile;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TermsAndConditionsVersionNotAcceptedTest {

    @Test
    void isMetShouldReturnTrueIfUserHasNotAcceptedCurrentVersion() {
        UserProfile userProfile = mock(UserProfile.class);
        TermsAndConditions termsAndConditions = mock(TermsAndConditions.class);
        when(userProfile.getTermsAndConditions()).thenReturn(termsAndConditions);
        when(termsAndConditions.getVersion()).thenReturn("1.0");
        TermsAndConditionsVersionNotAccepted condition =
                new TermsAndConditionsVersionNotAccepted("2.0");

        assertThat(condition.isMet(Optional.of(userProfile)), equalTo(true));
    }

    @Test
    void isMetShouldReturnFalseIfUserHasAcceptedCurrentVersion() {
        UserProfile userProfile = mock(UserProfile.class);
        TermsAndConditions termsAndConditions = mock(TermsAndConditions.class);
        when(userProfile.getTermsAndConditions()).thenReturn(termsAndConditions);
        when(termsAndConditions.getVersion()).thenReturn("1.0");
        TermsAndConditionsVersionNotAccepted condition =
                new TermsAndConditionsVersionNotAccepted("1.0");

        assertThat(condition.isMet(Optional.of(userProfile)), equalTo(false));
    }
}
