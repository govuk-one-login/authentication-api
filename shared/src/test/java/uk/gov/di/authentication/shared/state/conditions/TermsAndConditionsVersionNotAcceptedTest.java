package uk.gov.di.authentication.shared.state.conditions;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.NoSuchElementException;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
        UserContext userContext =
                UserContext.builder(mock(Session.class)).withUserProfile(userProfile).build();
        assertThat(condition.isMet(Optional.of(userContext)), equalTo(true));
    }

    @Test
    void isMetShouldReturnFalseIfUserHasAcceptedCurrentVersion() {
        UserProfile userProfile = mock(UserProfile.class);
        TermsAndConditions termsAndConditions = mock(TermsAndConditions.class);
        when(userProfile.getTermsAndConditions()).thenReturn(termsAndConditions);
        when(termsAndConditions.getVersion()).thenReturn("1.0");
        TermsAndConditionsVersionNotAccepted condition =
                new TermsAndConditionsVersionNotAccepted("1.0");
        UserContext userContext =
                UserContext.builder(mock(Session.class)).withUserProfile(userProfile).build();

        assertThat(condition.isMet(Optional.of(userContext)), equalTo(false));
    }

    @Test
    void shouldThrowIfUserProfileNotPresent() {
        TermsAndConditionsVersionNotAccepted condition =
                new TermsAndConditionsVersionNotAccepted("1.0");
        UserContext userContext = UserContext.builder(mock(Session.class)).build();
        assertThrows(NoSuchElementException.class, () -> condition.isMet(Optional.of(userContext)));
    }
}
