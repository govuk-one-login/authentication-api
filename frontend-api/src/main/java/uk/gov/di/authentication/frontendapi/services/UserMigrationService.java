package uk.gov.di.authentication.frontendapi.services;

import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.services.AuthenticationService;

import java.util.Objects;

public class UserMigrationService {

    private final AuthenticationService authenticationService;

    public UserMigrationService(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    public boolean userHasBeenPartlyMigrated(String legacySubjectId, String email) {
        UserCredentials userCredentials = authenticationService.getUserCredentialsFromEmail(email);
        return Objects.nonNull(legacySubjectId) && Objects.isNull(userCredentials.getPassword());
    }
}
