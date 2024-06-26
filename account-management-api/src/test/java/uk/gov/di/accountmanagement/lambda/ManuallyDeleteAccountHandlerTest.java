package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.DeletedAccountIdentifiers;
import uk.gov.di.accountmanagement.services.ManualAccountDeletionService;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.AuthenticationService;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ManuallyDeleteAccountHandlerTest {
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ManualAccountDeletionService manualAccountDeletionService =
            mock(ManualAccountDeletionService.class);
    private static final Context CONTEXT = mock(Context.class);
    private final ManuallyDeleteAccountHandler underTest =
            new ManuallyDeleteAccountHandler(authenticationService, manualAccountDeletionService);

    @Test
    void callsRemoveAccountWithTheCorrectParameters() {
        // given
        var expectedEmail = "test@example.com";
        var userProfile = mock(UserProfile.class);
        when(authenticationService.getUserProfileByEmailMaybe(any()))
                .thenReturn(Optional.ofNullable(userProfile));
        when(manualAccountDeletionService.manuallyDeleteAccount(any()))
                .thenReturn(mock(DeletedAccountIdentifiers.class));

        // when
        underTest.handleRequest(expectedEmail, CONTEXT);

        // then
        verify(authenticationService).getUserProfileByEmailMaybe(expectedEmail);
        verify(manualAccountDeletionService).manuallyDeleteAccount(userProfile);
    }

    @Test
    void throwsAnExceptionWhenTheUserIsNotFound() {
        // given
        when(authenticationService.getUserProfileByEmailMaybe(any())).thenReturn(Optional.empty());

        // then
        assertThrows(
                RuntimeException.class, () -> underTest.handleRequest("test@example.com", CONTEXT));
    }

    @Test
    void returnsTheCorrectValue() {
        // given
        var deletedAccountIdentifiers =
                new DeletedAccountIdentifiers("publicSubject", "legacySubject", "subject");
        var expectedReturnValue =
                "DeletedAccountIdentifiers[publicSubjectId=publicSubject, legacySubjectId=legacySubject, subjectId=subject]";
        var userProfile = mock(UserProfile.class);
        when(authenticationService.getUserProfileByEmailMaybe(any()))
                .thenReturn(Optional.ofNullable(userProfile));
        when(manualAccountDeletionService.manuallyDeleteAccount(any()))
                .thenReturn(deletedAccountIdentifiers);

        // when
        var actualReturnValue = underTest.handleRequest("test@example.com", CONTEXT);

        // then
        assertEquals(expectedReturnValue, actualReturnValue);
    }
}
