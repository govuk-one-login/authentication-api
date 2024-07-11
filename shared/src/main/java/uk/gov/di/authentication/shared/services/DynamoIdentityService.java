package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.IdentityCredentials;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;

public class DynamoIdentityService extends BaseDynamoService<IdentityCredentials> {

    private final long timeToExist;

    public DynamoIdentityService(ConfigurationService configurationService) {
        super(IdentityCredentials.class, "identity-credentials", configurationService);
        this.timeToExist = configurationService.getAccessTokenExpiry();
    }

    public void addCoreIdentityJWT(String subjectID, String coreIdentityJWT) {
        var identityCredentials =
                get(subjectID)
                        .orElse(new IdentityCredentials())
                        .withSubjectID(subjectID)
                        .withCoreIdentityJWT(coreIdentityJWT)
                        .withTimeToExist(
                                NowHelper.nowPlus(timeToExist, ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond());

        update(identityCredentials);
    }

    public Optional<IdentityCredentials> getIdentityCredentials(String subjectID) {
        return get(subjectID)
                .filter(t -> t.getTimeToExist() > NowHelper.now().toInstant().getEpochSecond());
    }

    public void saveIdentityClaims(
            String subjectID,
            Map<String, String> additionalClaims,
            String ipvVot,
            String ipvCoreIdentity) {
        var identityCredentials =
                new IdentityCredentials()
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
