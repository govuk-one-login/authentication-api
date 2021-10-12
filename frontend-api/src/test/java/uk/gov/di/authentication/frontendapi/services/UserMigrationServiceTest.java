package uk.gov.di.authentication.frontendapi.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.services.AuthenticationService;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class UserMigrationServiceTest {

    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private UserMigrationService userMigrationService;
    private static final String TEST_EMAIL = "test@digital.cabinet-office.gov.uk";
    private static final String LEGACY_SUBJECT = "some-subject";
    private static final String LEGACY_PASSWORD_ENCRYPTED =
            "$2y$05$pfRGAcOQjcxAc07N/6Ju1OwYYKIuCiGtGmk7L0Fjb.qBKGOYv4msK";
    private static final String LEGACY_PASSWORD_DECRYPTED = "password000";

    @BeforeEach
    public void setUp() {
        userMigrationService = new UserMigrationService(authenticationService);
    }

    @Test
    public void shouldReturnTrueIfUserHasBeenPartlyMigrated() {
        when(authenticationService.getUserCredentialsFromEmail(TEST_EMAIL))
                .thenReturn(generateUserCredentials(null, "migrated-password"));
        assertTrue(userMigrationService.userHasBeenPartlyMigrated(LEGACY_SUBJECT, TEST_EMAIL));
    }

    @Test
    public void shouldReturnFalseIfUserHasAlreadyBeenFullyMigrated() {
        when(authenticationService.getUserCredentialsFromEmail(TEST_EMAIL))
                .thenReturn(generateUserCredentials("sign-in-password", "migrated-password"));
        assertFalse(userMigrationService.userHasBeenPartlyMigrated(LEGACY_SUBJECT, TEST_EMAIL));
    }

    @Test
    public void shouldReturnFalseIfUserDoesNotHaveALegacySubjectId() {
        when(authenticationService.getUserCredentialsFromEmail(TEST_EMAIL))
                .thenReturn(generateUserCredentials("sign-in-password", null));

        assertFalse(userMigrationService.userHasBeenPartlyMigrated(null, TEST_EMAIL));
        verify(authenticationService, never())
                .migrateLegacyPassword(TEST_EMAIL, LEGACY_PASSWORD_DECRYPTED);
    }

    @Test
    public void shouldReturnTrueIfMigratedUserHasEnteredCorrectCredentials() {
        when(authenticationService.getUserCredentialsFromEmail(TEST_EMAIL))
                .thenReturn(generateUserCredentials("sign-in-password", LEGACY_PASSWORD_ENCRYPTED));

        assertTrue(userMigrationService.processMigratedUser(TEST_EMAIL, LEGACY_PASSWORD_DECRYPTED));
        verify(authenticationService).migrateLegacyPassword(TEST_EMAIL, LEGACY_PASSWORD_DECRYPTED);
    }

    @Test
    public void shouldReturnFalseIfMigratedUserHasEnteredIncorrectCredentials() {
        when(authenticationService.getUserCredentialsFromEmail(TEST_EMAIL))
                .thenReturn(generateUserCredentials("sign-in-password", LEGACY_PASSWORD_ENCRYPTED));
        assertFalse(userMigrationService.processMigratedUser(TEST_EMAIL, "wrong-password"));
    }

    private UserCredentials generateUserCredentials(
            String signInPassword, String migratedPassword) {
        return new UserCredentials()
                .setEmail(TEST_EMAIL)
                .setPassword(signInPassword)
                .setMigratedPassword(migratedPassword);
    }
}
