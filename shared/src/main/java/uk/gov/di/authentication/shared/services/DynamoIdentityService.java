package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.AuthIdentityCredentials;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;

public class DynamoIdentityService extends BaseDynamoService<AuthIdentityCredentials> {

    private final long timeToExist;

    public DynamoIdentityService(ConfigurationService configurationService) {
        super(AuthIdentityCredentials.class, "identity-credentials", configurationService);
        this.timeToExist = configurationService.getAccessTokenExpiry();
    }

    public void addCoreIdentityJWT(String subjectID, String coreIdentityJWT) {
        var identityCredentials =
                get(subjectID)
                        .orElse(new AuthIdentityCredentials())
                        .withSubjectID(subjectID)
                        .withCoreIdentityJWT(coreIdentityJWT)
                        .withTimeToExist(
                                NowHelper.nowPlus(timeToExist, ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond());

        update(identityCredentials);
    }

    public Optional<AuthIdentityCredentials> getIdentityCredentials(String subjectID) {
        return get(subjectID)
                .filter(t -> t.getTimeToExist() > NowHelper.now().toInstant().getEpochSecond());
    }

    public void deleteIdentityCredentials(String subjectID) {
        delete(subjectID);
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

        put(identityCredentials);
    }
}
