package uk.gov.di.authentication.accountdata.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.accountdata.entity.passkey.Passkey;
import uk.gov.di.authentication.accountdata.entity.passkey.PasskeysCreateRequest;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysCreateServiceFailureReason;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.time.LocalDateTime;

import static uk.gov.di.authentication.accountdata.helpers.PasskeysHelper.buildSortKey;

public class PasskeysService {

    private static final Logger LOG = LogManager.getLogger(PasskeysService.class);
    private final DynamoPasskeyService dynamoPasskeyService;
    private final ConfigurationService configurationService;

    public PasskeysService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.dynamoPasskeyService = new DynamoPasskeyService(configurationService);
    }

    public PasskeysService(
            ConfigurationService configurationService, DynamoPasskeyService dynamoPasskeyService) {
        this.configurationService = configurationService;
        this.dynamoPasskeyService = dynamoPasskeyService;
    }

    public Result<PasskeysCreateServiceFailureReason, Void> createPasskey(
            PasskeysCreateRequest passkeysCreateRequest, String publicSubjectId) {
        boolean passkeyCreated;
        var passkeyId = passkeysCreateRequest.passkeyId();

        try {
            var created = LocalDateTime.now().toString();
            var passkey =
                    new Passkey()
                            .withPublicSubjectId(publicSubjectId)
                            .withSortKey(buildSortKey(passkeyId))
                            .withCredentialId(passkeyId)
                            .withCreated(created)
                            .withCredential(passkeysCreateRequest.credential())
                            .withPasskeyAaguid(passkeysCreateRequest.aaguid())
                            .withPasskeyIsAttested(passkeysCreateRequest.isAttested())
                            .withPasskeySignCount(passkeysCreateRequest.signCount())
                            .withPasskeyTransports(passkeysCreateRequest.transports())
                            .withPasskeyBackupEligible(passkeysCreateRequest.isBackUpEligible())
                            .withPasskeyBackedUp(passkeysCreateRequest.isBackedUp());
            passkeyCreated = dynamoPasskeyService.savePasskeyIfUnique(passkey);
        } catch (Exception e) {
            LOG.error("Failed to save passkey", e);
            return Result.failure(PasskeysCreateServiceFailureReason.FAILED_TO_SAVE_PASSKEY);
        }

        if (!passkeyCreated) {
            LOG.error(
                    "Passkey with id {} already exists for user with subjectId {}",
                    passkeyId,
                    publicSubjectId);
            return Result.failure(PasskeysCreateServiceFailureReason.PASSKEY_EXISTS);
        }

        return Result.success(null);
    }
}
