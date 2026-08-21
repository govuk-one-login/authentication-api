package uk.gov.di.accountmanagement.services;

import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.AccountDataScope;
import uk.gov.di.authentication.shared.entity.JwtFailureReason;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.AccessTokenConstructorService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.List;

public class InactiveAccountDeletionTokenService {

    private static final Logger LOG =
            LogManager.getLogger(InactiveAccountDeletionTokenService.class);

    private static final long ACCESS_TOKEN_LIFETIME_MINUTES = 5L;

    private final ConfigurationService configurationService;
    private final AccessTokenConstructorService accessTokenConstructorService;
    private final NowHelper.NowClock nowClock;

    public InactiveAccountDeletionTokenService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.accessTokenConstructorService =
                new AccessTokenConstructorService(configurationService);
        this.nowClock = new NowHelper.NowClock(Clock.systemUTC());
    }

    public InactiveAccountDeletionTokenService(
            ConfigurationService configurationService,
            AccessTokenConstructorService accessTokenConstructorService,
            NowHelper.NowClock nowClock) {
        this.configurationService = configurationService;
        this.accessTokenConstructorService = accessTokenConstructorService;
        this.nowClock = nowClock;
    }

    public Result<JwtFailureReason, BearerAccessToken> createAccountDataApiAccessToken(
            String publicSubjectId) {
        return accessTokenConstructorService
                .createSignedAccessToken(
                        publicSubjectId,
                        List.of(AccountDataScope.ACCOUNT_DELETE),
                        nowClock.now(),
                        nowClock.nowPlus(ACCESS_TOKEN_LIFETIME_MINUTES, ChronoUnit.MINUTES),
                        configurationService.getAuthToAccountDataApiAudience(),
                        configurationService.getAuthIssuerClaim(),
                        configurationService.getInactiveAccountDeletionClientId(),
                        configurationService.getAuthToAccountDataSigningKey())
                .mapFailure(
                        failure -> {
                            LOG.error(
                                    "Error creating account-delete access token for inactive account deletion. Error: {}",
                                    failure);
                            return failure;
                        });
    }
}
