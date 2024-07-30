package uk.gov.di.authentication.frontendapi.services;

import org.bouncycastle.crypto.generators.BCrypt;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.*;

class UserMigrationServiceTest {

    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private UserMigrationService userMigrationService;
    private static final String LEGACY_SUBJECT = "some-subject";
    private static final String LEGACY_PASSWORD_DECRYPTED = buildTestPassword("legacy");
    private static final String SALT = "0123456789abcdef"; // pragma: allowlist secret
    private static final String PEPPER = "CUokSd0tqVvM64dEiGNe9-LwZoE"; // pragma: allowlist secret
    private static final String LEGACY_PASSWORD_ENCRYPTED =
            bcryptEncryptPassword(LEGACY_PASSWORD_DECRYPTED, SALT, PEPPER);

    @BeforeEach
    public void setUp() {
        when(configurationService.getPasswordPepper()).thenReturn(Optional.of(PEPPER));
        userMigrationService =
                new UserMigrationService(authenticationService, configurationService);
    }

    @Test
    public void shouldReturnTrueIfUserHasBeenPartlyMigrated() {
        var credentials = generateUserCredentials(null, PASSWORD_NEW);

        when(authenticationService.getUserCredentialsFromEmail(EMAIL)).thenReturn(credentials);

        assertTrue(userMigrationService.userHasBeenPartlyMigrated(LEGACY_SUBJECT, credentials));
    }

    @Test
    public void shouldReturnFalseIfUserHasAlreadyBeenFullyMigrated() {
        var credentials = generateUserCredentials(PASSWORD_NEW, buildTestPassword("migrated"));

        when(authenticationService.getUserCredentialsFromEmail(EMAIL)).thenReturn(credentials);

        assertFalse(userMigrationService.userHasBeenPartlyMigrated(LEGACY_SUBJECT, credentials));
    }

    @Test
    public void shouldReturnFalseIfUserDoesNotHaveALegacySubjectId() {
        var credentials = generateUserCredentials(PASSWORD_NEW, null);

        when(authenticationService.getUserCredentialsFromEmail(EMAIL)).thenReturn(credentials);

        assertFalse(userMigrationService.userHasBeenPartlyMigrated(null, credentials));
        verify(authenticationService, never())
                .migrateLegacyPassword(EMAIL, LEGACY_PASSWORD_DECRYPTED);
    }

    @Test
    public void shouldReturnTrueIfMigratedUserHasEnteredCorrectCredentials() {
        var credentials = generateUserCredentials(PASSWORD_NEW, LEGACY_PASSWORD_ENCRYPTED);

        when(authenticationService.getUserCredentialsFromEmail(EMAIL)).thenReturn(credentials);

        assertTrue(
                userMigrationService.processMigratedUser(credentials, LEGACY_PASSWORD_DECRYPTED));
        verify(authenticationService).migrateLegacyPassword(EMAIL, LEGACY_PASSWORD_DECRYPTED);
    }

    @Test
    public void shouldReturnFalseIfMigratedUserHasEnteredIncorrectCredentials() {
        var credentials = generateUserCredentials(PASSWORD_NEW, LEGACY_PASSWORD_ENCRYPTED);

        when(authenticationService.getUserCredentialsFromEmail(EMAIL)).thenReturn(credentials);
        assertFalse(userMigrationService.processMigratedUser(credentials, PASSWORD_BAD));
    }

    private UserCredentials generateUserCredentials(String newPassword, String migratedPassword) {
        return new UserCredentials()
                .withEmail(EMAIL)
                .withPassword(newPassword)
                .withMigratedPassword(migratedPassword);
    }

    private static String bcryptEncryptPassword(String password, String salt, String pepper) {
        char[] passwordChar = (password + pepper).toCharArray();

        byte[] passwordBytes = BCrypt.passwordToByteArray(passwordChar);
        byte[] saltBytes = salt.getBytes(StandardCharsets.UTF_8);

        return OpenBSDBCrypt.generate("2a", passwordBytes, saltBytes, 5);
    }
}
