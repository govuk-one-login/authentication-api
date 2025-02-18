package uk.gov.di.orchestration.shared.services;

import uk.gov.di.orchestration.shared.entity.AuthIdentityCredentials;
import uk.gov.di.orchestration.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;

public class DynamoIdentityService {

    private final long timeToExist;
    private final BaseDynamoService<AuthIdentityCredentials> authIdentityCredentialsDynamoService;

    public DynamoIdentityService(ConfigurationService configurationService) {
        authIdentityCredentialsDynamoService =
                new BaseDynamoService<>(
                        AuthIdentityCredentials.class,
                        "identity-credentials",
                        configurationService);
        this.timeToExist = configurationService.getAccessTokenExpiry();
    }

    public void addCoreIdentityJWT(String subjectID, String coreIdentityJWT) {
        var identityCredentials =
                authIdentityCredentialsDynamoService
                        .get(subjectID)
                        .orElse(new AuthIdentityCredentials())
                        .withSubjectID(subjectID)
                        .withCoreIdentityJWT(coreIdentityJWT)
                        .withTimeToExist(
                                NowHelper.nowPlus(timeToExist, ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond());

        authIdentityCredentialsDynamoService.update(identityCredentials);
    }

    public Optional<AuthIdentityCredentials> getIdentityCredentials(String subjectID) {
        return authIdentityCredentialsDynamoService
                .get(subjectID)
                .filter(t -> t.getTimeToExist() > NowHelper.now().toInstant().getEpochSecond());
    }

    public void deleteIdentityCredentials(String subjectID) {
        authIdentityCredentialsDynamoService.delete(subjectID);
    }

    public void saveIdentityClaims(
            String subjectID,
            Map<String, String> additionalClaims,
            String ipvVot,
            String ipvCoreIdentity) {
        var identityCredentials =
                new AuthIdentityCredentials()
                        .withSubjectID(subjectID)
                        .withAdditionalClaims(additionalClaims)
                        .withIpvVot(ipvVot)
                        .withIpvCoreIdentity(ipvCoreIdentity)
                        .withTimeToExist(
                                NowHelper.nowPlus(timeToExist, ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond());

        authIdentityCredentialsDynamoService.put(identityCredentials);
    }
}
