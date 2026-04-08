package uk.gov.di.accountmanagement.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.SdkBytes;
import uk.gov.di.accountmanagement.entity.AccountDeletionReason;
import uk.gov.di.accountmanagement.entity.DeletedAccountIdentifiers;
import uk.gov.di.accountmanagement.entity.LegacyAccountDeletionMessage;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.net.URI;
import java.util.Optional;

public class ManualAccountDeletionService {
    private final AccountDeletionService accountDeletionService;
    private final AwsSnsClient legacyAccountDeletionSnsClient;
    private final ConfigurationService configurationService;
    private static final Logger LOG = LogManager.getLogger(ManualAccountDeletionService.class);

    public ManualAccountDeletionService(
            AccountDeletionService accountDeletionService,
            AwsSnsClient legacyAccountDeletionSnsClient,
            ConfigurationService configurationService) {
        this.accountDeletionService = accountDeletionService;
        this.legacyAccountDeletionSnsClient = legacyAccountDeletionSnsClient;
        this.configurationService = configurationService;
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
        var legacyAccountDeletionMessage =
                new LegacyAccountDeletionMessage(
                        userProfile.getPublicSubjectID(),
                        userProfile.getLegacySubjectID(),
                        getCommonSubjectId(userProfile));
        try {
            accountDeletionService.removeAccount(
                    Optional.empty(),
                    userProfile,
                    Optional.empty(),
                    accountDeletionReason,
                    sendNotification);
            var deletedAccountPayload =
                    SerializationService.getInstance()
                            .writeValueAsString(legacyAccountDeletionMessage);
            legacyAccountDeletionSnsClient.publish(deletedAccountPayload);
            return accountIdentifiers;
        } catch (Json.JsonException e) {
            LOG.error(
                    "Error while deleting account: {}. Identifiers: {}",
                    e.getMessage(),
                    accountIdentifiers);
            throw new RuntimeException(e);
        }
    }

    private String getCommonSubjectId(UserProfile userProfile) {
        var internalSectorUri = URI.create(configurationService.getInternalSectorUri());
        var salt = SdkBytes.fromByteBuffer(userProfile.getSalt()).asByteArray();
        return ClientSubjectHelper.calculatePairwiseIdentifier(
                userProfile.getSubjectID(), internalSectorUri, salt);
    }
}
