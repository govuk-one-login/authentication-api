package uk.gov.di.authentication.accountdata.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.accountdata.entity.passkey.PasskeysCreateFailureReason;
import uk.gov.di.authentication.accountdata.entity.passkey.PasskeysCreateRequest;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.UUID;

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

    public Result<PasskeysCreateFailureReason, Void> createPasskey(
            PasskeysCreateRequest passkeysCreateRequest, String publicSubjectId) {

        var validatePasskeysCreateRequestResult =
                validatePasskeysCreateRequest(passkeysCreateRequest);
        if (validatePasskeysCreateRequestResult.isFailure()) {
            return validatePasskeysCreateRequestResult;
        }

        boolean passkeyCreated;
        try {
            passkeyCreated =
                    dynamoPasskeyService.savePasskeyIfUnique(
                            publicSubjectId,
                            passkeysCreateRequest.getCredential(),
                            passkeysCreateRequest.getPasskeyId(),
                            passkeysCreateRequest.getAaguid(),
                            passkeysCreateRequest.getIsAttested(),
                            passkeysCreateRequest.getSignCount(),
                            passkeysCreateRequest.getTransports(),
                            passkeysCreateRequest.getIsBackUpEligible(),
                            passkeysCreateRequest.getIsBackedUp());
        } catch (Exception e) {
            LOG.error("Failed to save passkey", e);
            return Result.failure(PasskeysCreateFailureReason.FAILED_TO_SAVE_PASSKEY);
        }

        if (!passkeyCreated) {
            LOG.error(
                    "Passkey with id {} already exists for user with subjectId {}",
                    passkeysCreateRequest.getPasskeyId(),
                    publicSubjectId);
            return Result.failure(PasskeysCreateFailureReason.PASSKEY_EXISTS);
        }

        return Result.success(null);
    }

    private Result<PasskeysCreateFailureReason, Void> validatePasskeysCreateRequest(
            PasskeysCreateRequest passkeysCreateRequest) {
        if (!isAaguidValid(passkeysCreateRequest.getAaguid())) {
            return Result.failure(PasskeysCreateFailureReason.INVALID_AAGUID);
        } else {
            return Result.success(null);
        }
    }

    private boolean isAaguidValid(String aaguid) {
        if (aaguid == null || aaguid.trim().isEmpty()) {
            return false;
        }

        try {
            UUID.fromString(aaguid);
        } catch (IllegalArgumentException e) {
            return false;
        }

        return true;
    }
}
