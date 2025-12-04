package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.entity.OrchIdentityCredentials;
import uk.gov.di.orchestration.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;

public class DynamoIdentityService extends BaseDynamoService<OrchIdentityCredentials> {

    private static final Logger LOG = LogManager.getLogger(DynamoIdentityService.class);
    private final long timeToExist;

    public DynamoIdentityService(ConfigurationService configurationService) {
        super(
                OrchIdentityCredentials.class,
                "Orch-Identity-Credentials",
                configurationService,
                true);
        this.timeToExist = configurationService.getAccessTokenExpiry();
    }

    public void addCoreIdentityJWT(
            String clientSessionId, String subjectID, String coreIdentityJWT) {
        LOG.info("Getting indentity credentials");
        var identityCredentials =
                get(clientSessionId)
                        .orElseGet(
                                () -> {
                                    LOG.info(
                                            "Couldnt find identity credentials, creating new ones with provided data");
                                    return new OrchIdentityCredentials();
                                })
                        .withClientSessionId(clientSessionId)
                        .withSubjectID(subjectID)
                        .withCoreIdentityJWT(coreIdentityJWT)
                        .withTimeToExist(
                                NowHelper.nowPlus(timeToExist, ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond());
        LOG.info("Updating identity credentials");
        update(identityCredentials);
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
            String ipvCoreIdentity) {
        var identityCredentials =
                new OrchIdentityCredentials()
                        .withClientSessionId(clientSessionId)
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
