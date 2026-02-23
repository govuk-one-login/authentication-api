package uk.gov.di.orchestration.shared.services;

import uk.gov.di.orchestration.shared.entity.OrchIdentityCredentials;
import uk.gov.di.orchestration.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;

public class DynamoIdentityService extends BaseDynamoService<OrchIdentityCredentials> {

    private final long timeToExist;

    public DynamoIdentityService(ConfigurationService configurationService) {
        super(
                OrchIdentityCredentials.class,
                "Orch-Identity-Credentials",
                configurationService,
                true);
        this.timeToExist = configurationService.getAccessTokenExpiry();
    }

    public OrchIdentityCredentials addCoreIdentityJWT(
            String clientSessionId, String subjectID, String coreIdentityJWT) {
        var identityCredentials =
                get(clientSessionId)
                        .orElse(new OrchIdentityCredentials())
                        .withClientSessionId(clientSessionId)
                        .withSubjectID(subjectID)
                        .withCoreIdentityJWT(coreIdentityJWT)
                        .withTimeToExist(
                                NowHelper.nowPlus(timeToExist, ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond());
        update(identityCredentials);
        return identityCredentials;
    }

    public Optional<OrchIdentityCredentials> getIdentityCredentials(String clientSessionId) {
        return get(clientSessionId)
                .filter(t -> t.getTimeToExist() > NowHelper.now().toInstant().getEpochSecond());
    }

    public void deleteIdentityCredentials(String clientSessionId) {
        delete(clientSessionId);
    }

    public void saveIdentityClaims(
            String clientSessionId,
            String subjectID,
            Map<String, String> additionalClaims,
            String ipvVot,
            String ipvCoreIdentity,
            Long spotQueuedAt) {
        var identityCredentials =
                new OrchIdentityCredentials()
                        .withClientSessionId(clientSessionId)
                        .withSubjectID(subjectID)
                        .withAdditionalClaims(additionalClaims)
                        .withIpvVot(ipvVot)
                        .withIpvCoreIdentity(ipvCoreIdentity)
                        .withSpotQueuedAtMs(spotQueuedAt)
                        .withTimeToExist(
                                NowHelper.nowPlus(timeToExist, ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond());
        put(identityCredentials);
    }
}
