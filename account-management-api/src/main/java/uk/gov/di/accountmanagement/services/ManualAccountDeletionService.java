package uk.gov.di.accountmanagement.services;

import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.accountmanagement.entity.AccountDeletionReason;
import uk.gov.di.accountmanagement.entity.DeletedAccountIdentifiers;
import uk.gov.di.authentication.shared.entity.JwtFailureReason;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

public class ManualAccountDeletionService {
    private final AccountDeletionService accountDeletionService;
    private final ConfigurationService configurationService;
    private final AccountDeletionTokenService accountDeletionTokenService;
    private final String clientId;
    private static final Logger LOG = LogManager.getLogger(ManualAccountDeletionService.class);

    public ManualAccountDeletionService(
            AccountDeletionService accountDeletionService,
            ConfigurationService configurationService) {
        this(accountDeletionService, configurationService, null, null);
    }

    public ManualAccountDeletionService(
            AccountDeletionService accountDeletionService,
            ConfigurationService configurationService,
            AccountDeletionTokenService accountDeletionTokenService,
            String clientId) {
        this.accountDeletionService = accountDeletionService;
        this.configurationService = configurationService;
        this.accountDeletionTokenService = accountDeletionTokenService;
        this.clientId = clientId;
    }

    public DeletedAccountIdentifiers manuallyDeleteAccount(UserProfile userProfile) {
        return manuallyDeleteAccount(userProfile, AccountDeletionReason.SUPPORT_INITIATED, true);
    }

    public DeletedAccountIdentifiers manuallyDeleteAccount(
            UserProfile userProfile,
            AccountDeletionReason accountDeletionReason,
            boolean sendNotification) {
        var accountIdentifiers =
                new DeletedAccountIdentifiers(
                        userProfile.getPublicSubjectID(),
                        userProfile.getLegacySubjectID(),
                        userProfile.getSubjectID());

        try {
            if (accountDeletionTokenService == null
                    || !configurationService.isAccountDeletionDataApiEnabled()) {
                accountDeletionService.removeAccount(
                        userProfile, AuditService.UNKNOWN, accountDeletionReason, sendNotification);

            } else {
                Result<JwtFailureReason, BearerAccessToken> adapiTokenResult =
                        accountDeletionTokenService.createAccountDataApiAccessToken(
                                userProfile.getPublicSubjectID(), clientId);

                if (adapiTokenResult.isFailure()) {
                    throw new RuntimeException(
                            "Failed to mint account-delete token for publicSubjectId: "
                                    + userProfile.getPublicSubjectID()
                                    + ". Reason: "
                                    + adapiTokenResult.getFailure());
                }

                accountDeletionService.removeAccount(
                        userProfile,
                        AuditService.UNKNOWN,
                        accountDeletionReason,
                        sendNotification,
                        adapiTokenResult.getSuccess().getValue());
            }
        } catch (RuntimeException e) {
            LOG.error(
                    "Error while deleting account: {}. Identifiers: {}",
                    e.getMessage(),
                    accountIdentifiers);
            throw e;
        }

        return accountIdentifiers;
    }
}
