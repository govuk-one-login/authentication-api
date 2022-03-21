package uk.gov.di.authentication.frontendapi.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class UserMigrationServiceTest {

    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private UserMigrationService userMigrationService;
    private static final String TEST_EMAIL = "test@digital.cabinet-office.gov.uk";
    private static final String LEGACY_SUBJECT = "some-subject";
    private static final String LEGACY_PASSWORD_ENCRYPTED =
            "$2a$05$2m1Swyvp.1UUWF3whZf4/e5bHFe/5G0I25txZOQ/zBJzWQWeZjPZK";
    private static final String LEGACY_PASSWORD_DECRYPTED = "password000";
    private static final String TEST_PEPPER = "CUokSd0tqVvM64dEiGNe9-LwZoE";

    @BeforeEach
    public void setUp() {
        when(configurationService.getPasswordPepper()).thenReturn(Optional.of(TEST_PEPPER));
        userMigrationService =
                new UserMigrationService(authenticationService, configurationService);
    }

    @Test
    public void shouldReturnTrueIfUserHasBeenPartlyMigrated() {
        var credentials = generateUserCredentials(null, "migrated-password");

        when(authenticationService.getUserCredentialsFromEmail(TEST_EMAIL)).thenReturn(credentials);

        assertTrue(userMigrationService.userHasBeenPartlyMigrated(LEGACY_SUBJECT, credentials));
    }

    @Test
    public void shouldReturnFalseIfUserHasAlreadyBeenFullyMigrated() {
        var credentials = generateUserCredentials("sign-in-password", "migrated-password");

        when(authenticationService.getUserCredentialsFromEmail(TEST_EMAIL)).thenReturn(credentials);

        assertFalse(userMigrationService.userHasBeenPartlyMigrated(LEGACY_SUBJECT, credentials));
    }

    @Test
    public void shouldReturnFalseIfUserDoesNotHaveALegacySubjectId() {
        var credentials = generateUserCredentials("sign-in-password", null);

        when(authenticationService.getUserCredentialsFromEmail(TEST_EMAIL)).thenReturn(credentials);

        assertFalse(userMigrationService.userHasBeenPartlyMigrated(null, credentials));
        verify(authenticationService, never())
                .migrateLegacyPassword(TEST_EMAIL, LEGACY_PASSWORD_DECRYPTED);
    }

    @Test
    public void shouldReturnTrueIfMigratedUserHasEnteredCorrectCredentials() {
        var credentials = generateUserCredentials("sign-in-password", LEGACY_PASSWORD_ENCRYPTED);

        when(authenticationService.getUserCredentialsFromEmail(TEST_EMAIL)).thenReturn(credentials);

        assertTrue(
                userMigrationService.processMigratedUser(credentials, LEGACY_PASSWORD_DECRYPTED));
        verify(authenticationService).migrateLegacyPassword(TEST_EMAIL, LEGACY_PASSWORD_DECRYPTED);
    }

    @Test
    public void shouldReturnFalseIfMigratedUserHasEnteredIncorrectCredentials() {
        var credentials = generateUserCredentials("sign-in-password", LEGACY_PASSWORD_ENCRYPTED);

        when(authenticationService.getUserCredentialsFromEmail(TEST_EMAIL)).thenReturn(credentials);
        assertFalse(userMigrationService.processMigratedUser(credentials, "wrong-password"));
    }

    private UserCredentials generateUserCredentials(String newPassword, String migratedPassword) {
        return new UserCredentials()
                .setEmail(TEST_EMAIL)
                .setPassword(newPassword)
                .setMigratedPassword(migratedPassword);
    }
}
