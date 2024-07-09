package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.services.AccountDeletionService;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuthenticationService;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ManuallyDeleteAccountHandlerTest {
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AccountDeletionService accountDeletionService =
            mock(AccountDeletionService.class);
    private static final Context CONTEXT = mock(Context.class);
    private final ManuallyDeleteAccountHandler underTest =
            new ManuallyDeleteAccountHandler(authenticationService, accountDeletionService);

    @Test
    void callsRemoveAccountWithTheCorrectParameters() throws Json.JsonException {
        // given
        var expectedEmail = "test@example.com";
        var userProfile = mock(UserProfile.class);
        when(authenticationService.getUserProfileByEmailMaybe(any()))
                .thenReturn(Optional.ofNullable(userProfile));
        when(accountDeletionService.removeAccount(any(), any(), any()))
                .thenReturn(mock(AccountDeletionService.DeletedAccountIdentifiers.class));

        // when
        underTest.handleRequest(expectedEmail, CONTEXT);

        // then
        verify(authenticationService).getUserProfileByEmailMaybe(expectedEmail);
        verify(accountDeletionService)
                .removeAccount(Optional.empty(), userProfile, Optional.empty());
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
    void throwsAnExceptionWhenUserDeletionFails() throws Json.JsonException {
        // given
        var userProfile = mock(UserProfile.class);
        when(authenticationService.getUserProfileByEmailMaybe(any()))
                .thenReturn(Optional.ofNullable(userProfile));
        when(accountDeletionService.removeAccount(any(), any(), any()))
                .thenThrow(Json.JsonException.class);

        // then
        assertThrows(
                RuntimeException.class, () -> underTest.handleRequest("test@example.com", CONTEXT));
    }
}
