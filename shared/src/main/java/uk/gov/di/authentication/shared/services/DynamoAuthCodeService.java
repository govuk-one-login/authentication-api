package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.AuthCodeStore;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

public class DynamoAuthCodeService extends BaseDynamoService<AuthCodeStore> {

    private final long timeToExist;
    private final boolean isAuthOrchSplitEnabled;

    public DynamoAuthCodeService(
            ConfigurationService configurationService, boolean isAuthCodeStoreEnabled) {
        super(AuthCodeStore.class, "auth-code-store", configurationService);
        this.timeToExist = configurationService.getAuthCodeExpiry();
        this.isAuthOrchSplitEnabled = isAuthCodeStoreEnabled;
    }

    public DynamoAuthCodeService(ConfigurationService configurationService) {
        super(AuthCodeStore.class, "auth-code-store", configurationService);
        this.timeToExist = configurationService.getAuthCodeExpiry();
        this.isAuthOrchSplitEnabled = configurationService.isAuthOrchSplitEnabled();
    }

    public Optional<AuthCodeStore> getAuthCodeStore(String authCode) {
        if (isAuthOrchSplitEnabled) {
            return get(authCode)
                    .filter(t -> t.getTimeToExist() > NowHelper.now().toInstant().getEpochSecond());
        }
        return Optional.empty();
    }

    public void deleteAuthCode(String authCode) {
        if (isAuthOrchSplitEnabled) {
            delete(authCode);
        }
    }

    public void saveAuthCode(
            String subjectID,
            String authCode,
            List<String> claims,
            boolean hasBeenUsed,
            String sectorIdentifier,
            boolean isNewAccount) {
        if (isAuthOrchSplitEnabled) {
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
    }

    public void updateHasBeenUsed(String authCode, boolean hasBeenUsed) {
        if (isAuthOrchSplitEnabled) {
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
}
