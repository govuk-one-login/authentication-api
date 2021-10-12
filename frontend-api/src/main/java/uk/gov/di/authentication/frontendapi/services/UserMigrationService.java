package uk.gov.di.authentication.frontendapi.services;

import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.AuthenticationService;

import java.util.Objects;

public class UserMigrationService {

    private final AuthenticationService authenticationService;

    public UserMigrationService(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    public boolean userHasBeenPartlyMigrated(String email) {
        UserProfile userProfile = authenticationService.getUserProfileByEmail(email);
        UserCredentials userCredentials = authenticationService.getUserCredentialsFromEmail(email);
        return Objects.nonNull(userProfile.getLegacySubjectID())
                && Objects.isNull(userCredentials.getPassword());
    }
}
