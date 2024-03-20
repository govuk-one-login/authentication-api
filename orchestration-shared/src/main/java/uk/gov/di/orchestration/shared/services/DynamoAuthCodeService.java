package uk.gov.di.orchestration.shared.services;

import uk.gov.di.orchestration.shared.entity.AuthCodeStore;
import uk.gov.di.orchestration.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

public class DynamoAuthCodeService extends BaseDynamoService<AuthCodeStore> {

    private final long timeToExist;

    public DynamoAuthCodeService(ConfigurationService configurationService) {
        super(AuthCodeStore.class, "auth-code-store", configurationService);
        this.timeToExist = configurationService.getAuthCodeExpiry();
    }

    public Optional<AuthCodeStore> getAuthCodeStore(String authCode) {
        return get(authCode)
                .filter(t -> t.getTimeToExist() > NowHelper.now().toInstant().getEpochSecond());
    }

    public void deleteAuthCode(String authCode) {
        delete(authCode);
    }

    public void saveAuthCode(
            String subjectID,
            String authCode,
            List<String> claims,
            boolean hasBeenUsed,
            String sectorIdentifier,
            boolean isNewAccount) {
        var authCodeStore =
                new AuthCodeStore()
                        .withSubjectID(subjectID)
                        .withAuthCode(authCode)
                        .withClaims(claims)
                        .withHasBeenUsed(hasBeenUsed)
                        .withSectorIdentifier(sectorIdentifier)
                        .withIsNewAccount(isNewAccount)
                        .withTimeToExist(
                                NowHelper.nowPlus(timeToExist, ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond());

        put(authCodeStore);
    }

    public void updateHasBeenUsed(String authCode, boolean hasBeenUsed) {
        var authCodeStore =
                get(authCode)
                        .orElse(new AuthCodeStore())
                        .withAuthCode(authCode)
                        .withHasBeenUsed(hasBeenUsed)
                        .withTimeToExist(
                                NowHelper.nowPlus(timeToExist, ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond());

        update(authCodeStore);
    }
}
