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

public class PasskeysCreateService {

    private static final Logger LOG = LogManager.getLogger(PasskeysCreateService.class);
    private final DynamoPasskeyService dynamoPasskeyService;
    private final ConfigurationService configurationService;

    public PasskeysCreateService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.dynamoPasskeyService = new DynamoPasskeyService(configurationService);
    }

    public PasskeysCreateService(
            ConfigurationService configurationService, DynamoPasskeyService dynamoPasskeyService) {
        this.configurationService = configurationService;
        this.dynamoPasskeyService = dynamoPasskeyService;
    }

    public Result<PasskeysCreateServiceFailureReason, Void> createPasskey(
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
                        .withPasskeyBackedUp(passkeysCreateRequest.isBackedUp());

        var result = dynamoPasskeyService.savePasskeyIfUnique(passkey);

        return result.fold(
                failure ->
                        switch (failure) {
                            case PASSKEY_EXISTS -> {
                                LOG.error(
                                        "Passkey with id {} already exists for user with subjectId {}",
                                        passkeyId,
                                        publicSubjectId);
                                yield Result.failure(
                                        PasskeysCreateServiceFailureReason.PASSKEY_EXISTS);
                            }
                            case FAILED_TO_SAVE_PASSKEY -> {
                                LOG.error("Failed to save passkey");
                                yield Result.failure(
                                        PasskeysCreateServiceFailureReason.FAILED_TO_SAVE_PASSKEY);
                            }
                        },
                success -> Result.success(null));
    }
}
