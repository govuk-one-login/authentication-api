package uk.gov.di.authentication.shared.services.permissions;

import uk.gov.di.authentication.shared.entity.AuthenticationAttempts;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.BaseDynamoService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;

public class UserPermissionService {
    private final ConfigurationService configurationService;
    private final BaseDynamoService<AuthenticationAttempts> authenticationAttemptsDynamoService;
    private final CodeStorageService codeStorageService;

    public UserPermissionService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.authenticationAttemptsDynamoService =
                new BaseDynamoService<>(
                        AuthenticationAttempts.class,
                        "authentication-attempt",
                        configurationService);
        this.codeStorageService = new CodeStorageService(configurationService);
    }

    public Result<UserPermissionCheckFailure, UserPermissionCheck> canVerifyPassword(
            UserProfile userProfile, String requestedEmail, JourneyType journeyType) {
        var isReauthJourney = journeyType.equals(JourneyType.REAUTHENTICATION);

        int count;
        if (isReauthJourney
                && configurationService.supportReauthSignoutEnabled()
                && configurationService.isAuthenticationAttemptsServiceEnabled()) {

            count =
                    this.getCount(
                            userProfile.getSubjectID(),
                            JourneyType.REAUTHENTICATION,
                            CountType.ENTER_PASSWORD);
        } else if (isReauthJourney) {
            count = codeStorageService.getIncorrectPasswordCountReauthJourney(requestedEmail);
        } else {
            count = codeStorageService.getIncorrectPasswordCount(requestedEmail);
        }

        UserPermissionStatus status =
                count >= configurationService.getMaxPasswordRetries()
                        ? UserPermissionStatus.DENIED
                        : UserPermissionStatus.ALLOWED;

        return Result.success(
                new UserPermissionCheck(status, new UserPermissionCheckContext(count)));
    }

    public void recordPasswordVerificationAttempt(
            UserProfile userProfile, JourneyType journeyType) {
        var isReauthJourney = journeyType.equals(JourneyType.REAUTHENTICATION);
        if (configurationService.supportReauthSignoutEnabled() && isReauthJourney) {
            if (configurationService.isAuthenticationAttemptsServiceEnabled()) {
                this.createOrIncrementCount(
                        userProfile.getSubjectID(),
                        NowHelper.nowPlus(
                                        configurationService.getReauthEnterPasswordCountTTL(),
                                        ChronoUnit.SECONDS)
                                .toInstant()
                                .getEpochSecond(),
                        JourneyType.REAUTHENTICATION,
                        CountType.ENTER_PASSWORD);
            } else {
                codeStorageService.increaseIncorrectPasswordCountReauthJourney(
                        userProfile.getEmail());
            }
        } else {
            codeStorageService.increaseIncorrectPasswordCount(userProfile.getEmail());
        }
    }

    // Below this line are deprecated public methods that need to go private
    public void createOrIncrementCount(
            String internalSubjectId, long ttl, JourneyType journeyType, CountType countType) {
        Optional<AuthenticationAttempts> authenticationAttempt =
                authenticationAttemptsDynamoService.get(
                        internalSubjectId, buildSortKey(journeyType, countType));
        if (authenticationAttempt.isPresent()) {
            if (isTTLExpired(authenticationAttempt.get().getTimeToLive())) {
                authenticationAttempt.get().setTimeToLive(ttl);
                authenticationAttempt.get().setCount(1);
            } else {
                authenticationAttempt.get().setCount(authenticationAttempt.get().getCount() + 1);
            }

        } else {
            authenticationAttempt =
                    Optional.ofNullable(
                            new AuthenticationAttempts()
                                    .withInternalSubjectId(internalSubjectId)
                                    .withCount(1)
                                    .withCountType(countType)
                                    .withJourneyType(journeyType)
                                    .withTimeToLive(ttl));
        }
        authenticationAttempt.ifPresent(authenticationAttemptsDynamoService::update);
    }

    public int getCount(String internalSubjectId, JourneyType journeyType, CountType countType) {
        long currentTimestamp = NowHelper.now().toInstant().getEpochSecond();
        var authenticationAttemptRecord =
                authenticationAttemptsDynamoService
                        .get(internalSubjectId, buildSortKey(journeyType, countType))
                        .filter(t -> t.getTimeToLive() > currentTimestamp);
        if (authenticationAttemptRecord.isEmpty()) {
            return 0;
        }
        return authenticationAttemptRecord.get().getCount();
    }

    public Map<CountType, Integer> getCountsByJourney(
            String internalSubjectId, JourneyType journeyType) {
        Map<CountType, Integer> results = new EnumMap<>(CountType.class);
        Arrays.stream(CountType.values())
                .forEach(
                        countType -> {
                            var count = getCount(internalSubjectId, journeyType, countType);
                            if (count > 0) {
                                results.put(countType, count);
                            }
                        });
        return results;
    }

    // This should only be used in specific journeys (e.g. reauth) where it's possible that a
    // non-logged in user
    // can go through a journey, and have counts initially stored against a pairwise id
    public Map<CountType, Integer> getCountsByJourneyForSubjectIdAndRpPairwiseId(
            String internalSubjectId, String rpPairwiseId, JourneyType journeyType) {
        Map<CountType, Integer> results = new EnumMap<>(CountType.class);
        Arrays.stream(CountType.values())
                .forEach(
                        countType -> {
                            var count =
                                    getCount(internalSubjectId, journeyType, countType)
                                            + getCount(rpPairwiseId, journeyType, countType);
                            if (count > 0) {
                                results.put(countType, count);
                            }
                        });
        return results;
    }

    public void deleteCount(
            String internalSubjectId, JourneyType journeyType, CountType countType) {
        authenticationAttemptsDynamoService.delete(
                internalSubjectId, buildSortKey(journeyType, countType));
    }

    public static String buildSortKey(JourneyType journeyType, CountType countType) {
        return journeyType.getValue() + "#" + countType.getValue() + "#" + "Count";
    }

    private boolean isTTLExpired(long ttl) {
        return (NowHelper.now().toInstant().getEpochSecond() > ttl);
    }
}
