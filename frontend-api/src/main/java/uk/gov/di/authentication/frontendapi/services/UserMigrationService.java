package uk.gov.di.authentication.frontendapi.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.generators.BCrypt;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Objects;
import java.util.Optional;

public class UserMigrationService {

    private static final Logger LOG = LogManager.getLogger(UserMigrationService.class);

    private final AuthenticationService authenticationService;
    private final ConfigurationService configurationService;

    public UserMigrationService(
            AuthenticationService authenticationService,
            ConfigurationService configurationService) {
        this.authenticationService = authenticationService;
        this.configurationService = configurationService;
    }

    public static boolean userHasBeenPartlyMigrated(
            String legacySubjectId, UserCredentials userCredentials) {
        return Objects.nonNull(legacySubjectId) && Objects.isNull(userCredentials.getPassword());
    }

    public boolean processMigratedUser(UserCredentials userCredentials, String inputPassword) {
        Optional<String> passwordPepper = configurationService.getPasswordPepper();
        char[] passwordChar =
                passwordPepper.map(t -> inputPassword + t).orElse(inputPassword).toCharArray();
        byte[] passwordByteArray = BCrypt.passwordToByteArray(passwordChar);

        boolean hasValidCredentials =
                OpenBSDBCrypt.checkPassword(
                        userCredentials.getMigratedPassword(), passwordByteArray);

        if (!hasValidCredentials) {
            LOG.info("Migrated user has invalid credentials");
            return hasValidCredentials;
        }
        LOG.info("Migrated user has valid credentials. About to migrate password");
        authenticationService.migrateLegacyPassword(userCredentials.getEmail(), inputPassword);
        return true;
    }
}
