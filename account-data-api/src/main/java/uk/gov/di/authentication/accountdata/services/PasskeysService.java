package uk.gov.di.authentication.accountdata.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.accountdata.entity.passkey.Passkey;
import uk.gov.di.authentication.accountdata.entity.passkey.PasskeysCreateRequest;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysCreateFailureReason;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysDeleteFailureReason;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysRetrieveFailureReasons;
import uk.gov.di.authentication.accountdata.entity.passkey.failurereasons.PasskeysUpdateFailureReason;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.time.LocalDateTime;
import java.util.List;

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

    public Result<PasskeysCreateFailureReason, Void> createPasskey(
            PasskeysCreateRequest passkeysCreateRequest, String publicSubjectId) {

        var passkeyId = passkeysCreateRequest.passkeyId();
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
                        .withPasskeyBackedUp(passkeysCreateRequest.isBackedUp())
                        .withPasskeyIsResidentKey(passkeysCreateRequest.isResidentKey());

        var result = dynamoPasskeyService.savePasskeyIfUnique(passkey);

        return result.fold(
                failure ->
                        switch (failure) {
                            case PASSKEY_EXISTS -> {
                                LOG.error(
                                        "Passkey with id {} already exists for user with subjectId {}",
                                        passkeyId,
                                        publicSubjectId);
                                yield result;
                            }
                            case FAILED_TO_SAVE_PASSKEY -> {
                                LOG.error("Failed to save passkey");
                                yield result;
                            }
                            default -> result;
                        },
                success -> Result.success(null));
    }

    public Result<PasskeysUpdateFailureReason, Passkey> updatePasskey(
            String publicSubjectId, String passkeyId, String lastUsedTime, int updatedSignCount) {
        try {
            return dynamoPasskeyService.updatePasskey(
                    publicSubjectId, passkeyId, lastUsedTime, updatedSignCount);
        } catch (Exception e) {
            LOG.error("Failed to update passkey", e);
            return Result.failure(PasskeysUpdateFailureReason.FAILED_TO_UPDATE_PASSKEY);
        }
    }

    public Result<PasskeysRetrieveFailureReasons, List<Passkey>> retrievePasskeys(
            String publicSubjectId) {
        try {
            var passkeysForUser = dynamoPasskeyService.getPasskeysForUser(publicSubjectId);
            return Result.success(passkeysForUser);
        } catch (Exception e) {
            LOG.error("Failed to retrieve passkeys", e);
            return Result.failure(PasskeysRetrieveFailureReasons.FAILED_TO_GET_PASSKEYS);
        }
    }

    public Result<PasskeysDeleteFailureReason, Void> deletePasskey(
            String publicSubjectId, String passkeyIdentifier) {
        try {
            return dynamoPasskeyService.deletePasskey(publicSubjectId, passkeyIdentifier);
        } catch (Exception e) {
            LOG.error("An exception occurred when attempting to delete passkey", e);
            return Result.failure(PasskeysDeleteFailureReason.FAILED_TO_DELETE_PASSKEY);
        }
    }
}
