package uk.gov.di.orchestration.shared.services;

import uk.gov.di.orchestration.shared.entity.AuthIdentityCredentials;
import uk.gov.di.orchestration.shared.entity.OrchIdentityCredentials;
import uk.gov.di.orchestration.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;

public class DynamoIdentityService {

    private final long timeToExist;
    private final BaseDynamoService<AuthIdentityCredentials> authIdentityCredentialsDynamoService;
    private final BaseDynamoService<OrchIdentityCredentials> orchIdentityCredentialsDynamoService;

    public DynamoIdentityService(ConfigurationService configurationService) {
        authIdentityCredentialsDynamoService =
                new BaseDynamoService<>(
                        AuthIdentityCredentials.class,
                        "identity-credentials",
                        configurationService);
        orchIdentityCredentialsDynamoService =
                new BaseDynamoService<>(
                        OrchIdentityCredentials.class,
                        "Orch-Identity-Credentials",
                        configurationService,
                        true);
        this.timeToExist = configurationService.getAccessTokenExpiry();
    }

    public void addCoreIdentityJWT(
            String clientSessionId, String subjectID, String coreIdentityJWT) {
        var authIdentityCredentials =
                authIdentityCredentialsDynamoService
                        .get(subjectID)
                        .orElse(new AuthIdentityCredentials())
                        .withSubjectID(subjectID)
                        .withCoreIdentityJWT(coreIdentityJWT)
                        .withTimeToExist(
                                NowHelper.nowPlus(timeToExist, ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond());
        authIdentityCredentialsDynamoService.update(authIdentityCredentials);

        var identityCredentials =
                orchIdentityCredentialsDynamoService
                        .get(clientSessionId)
                        .orElse(new OrchIdentityCredentials())
                        .withClientSessionId(clientSessionId)
                        .withSubjectID(subjectID)
                        .withCoreIdentityJWT(coreIdentityJWT)
                        .withTimeToExist(
                                NowHelper.nowPlus(timeToExist, ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond());
        orchIdentityCredentialsDynamoService.update(identityCredentials);
    }

    public Optional<OrchIdentityCredentials> getIdentityCredentials(String clientSessionId) {
        return orchIdentityCredentialsDynamoService
                .get(clientSessionId)
                .filter(t -> t.getTimeToExist() > NowHelper.now().toInstant().getEpochSecond());
    }

    public void deleteIdentityCredentials(String clientSessionId, String subjectID) {
        authIdentityCredentialsDynamoService.delete(subjectID);
        orchIdentityCredentialsDynamoService.delete(clientSessionId);
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
        orchIdentityCredentialsDynamoService.put(identityCredentials);
    }
}
