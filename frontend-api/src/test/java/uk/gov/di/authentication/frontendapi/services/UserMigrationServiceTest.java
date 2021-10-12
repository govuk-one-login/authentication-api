package uk.gov.di.authentication.frontendapi.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.AuthenticationService;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UserMigrationServiceTest {

    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private UserMigrationService userMigrationService;
    private static final String TEST_EMAIL = "test@digital.cabinet-office.gov.uk";
    private static final String LEGACY_SUBJECT = "some-subject";

    @BeforeEach
    public void setUp() {
        userMigrationService = new UserMigrationService(authenticationService);
    }

    @Test
    public void shouldReturnTrueIfUserHasBeenPartlyMigrated() {
        when(authenticationService.getUserProfileByEmail(TEST_EMAIL))
                .thenReturn(generateUserProfile(LEGACY_SUBJECT));
        when(authenticationService.getUserCredentialsFromEmail(TEST_EMAIL))
                .thenReturn(generateUserCredentials(null, "migrated-password"));
        assertTrue(userMigrationService.userHasBeenPartlyMigrated(TEST_EMAIL));
    }

    @Test
    public void shouldReturnFalseIfUserHasAlreadyBeenFullyMigrated() {
        when(authenticationService.getUserProfileByEmail(TEST_EMAIL))
                .thenReturn(generateUserProfile(LEGACY_SUBJECT));
        when(authenticationService.getUserCredentialsFromEmail(TEST_EMAIL))
                .thenReturn(generateUserCredentials("sign-in-password", "migrated-password"));
        assertFalse(userMigrationService.userHasBeenPartlyMigrated(TEST_EMAIL));
    }

    @Test
    public void shouldReturnFalseIfUserDoesNotHaveALegacySubjectId() {
        when(authenticationService.getUserProfileByEmail(TEST_EMAIL))
                .thenReturn(generateUserProfile(null));
        when(authenticationService.getUserCredentialsFromEmail(TEST_EMAIL))
                .thenReturn(generateUserCredentials("sign-in-password", null));
        assertFalse(userMigrationService.userHasBeenPartlyMigrated(TEST_EMAIL));
    }

    private UserCredentials generateUserCredentials(
            String signInPassword, String migratedPassword) {
        return new UserCredentials()
                .setEmail(TEST_EMAIL)
                .setPassword(signInPassword)
                .setMigratedPassword(migratedPassword);
    }

    private UserProfile generateUserProfile(String legacySubjectId) {
        return new UserProfile()
                .setEmail(TEST_EMAIL)
                .setEmailVerified(true)
                .setLegacySubjectID(legacySubjectId);
    }
}
