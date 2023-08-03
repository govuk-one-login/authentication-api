package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.AuthCodeStore;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.Optional;

public class DynamoAuthCodeService extends BaseDynamoService<AuthCodeStore> {

    private final long timeToExist;
    private final boolean isAuthCodeStoreEnabled;

    public DynamoAuthCodeService(
            ConfigurationService configurationService, boolean isAuthCodeStoreEnabled) {
        super(AuthCodeStore.class, "auth-code-store", configurationService);
        this.timeToExist = configurationService.getAuthCodeExpiry();
        this.isAuthCodeStoreEnabled = isAuthCodeStoreEnabled;
    }

    public DynamoAuthCodeService(ConfigurationService configurationService) {
        super(AuthCodeStore.class, "auth-code-store", configurationService);
        this.timeToExist = configurationService.getAuthCodeExpiry();
        this.isAuthCodeStoreEnabled = configurationService.isAuthCodeStoreEnabled();
    }

    public Optional<AuthCodeStore> getAuthCodeStore(String subjectID) {
        if (isAuthCodeStoreEnabled) {
            return get(subjectID)
                    .filter(t -> t.getTimeToExist() > NowHelper.now().toInstant().getEpochSecond());
        }
        return Optional.empty();
    }

    public void deleteAuthCode(String subjectID) {
        if (isAuthCodeStoreEnabled) {
            delete(subjectID);
        }
    }

    public void saveAuthCode(
            String subjectID, String authCode, String requestedScopeClaims, boolean hasBeenUsed) {
        if (isAuthCodeStoreEnabled) {
            var authCodeStore =
                    new AuthCodeStore()
                            .withSubjectID(subjectID)
                            .withAuthCode(authCode)
                            .withRequestedScopeClaims(requestedScopeClaims)
                            .withHasBeenUsed(hasBeenUsed)
                            .withTimeToExist(
                                    NowHelper.nowPlus(timeToExist, ChronoUnit.SECONDS)
                                            .toInstant()
                                            .getEpochSecond());

            put(authCodeStore);
        }
    }

    public void updateHasBeenUsed(String subjectID, boolean hasBeenUsed) {
        if (isAuthCodeStoreEnabled) {
            var authCode =
                    get(subjectID)
                            .orElse(new AuthCodeStore())
                            .withSubjectID(subjectID)
                            .withHasBeenUsed(hasBeenUsed)
                            .withTimeToExist(
                                    NowHelper.nowPlus(timeToExist, ChronoUnit.SECONDS)
                                            .toInstant()
                                            .getEpochSecond());

            update(authCode);
        }
    }
}
