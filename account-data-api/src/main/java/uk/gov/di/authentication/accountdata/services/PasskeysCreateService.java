package uk.gov.di.authentication.accountdata.services;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.accountdata.entity.passkey.PasskeysCreateFailureReason;
import uk.gov.di.authentication.accountdata.entity.passkey.PasskeysCreateRequest;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.List;
import java.util.UUID;

public class PasskeysCreateService {

    private static final Logger LOG = LogManager.getLogger(PasskeysCreateService.class);
    private final Json objectMapper = SerializationService.getInstance();
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
            APIGatewayProxyRequestEvent input) {
        PasskeysCreateRequest passkeysCreateRequest;
        try {
            passkeysCreateRequest =
                    objectMapper.readValue(input.getBody(), PasskeysCreateRequest.class, true);
        } catch (Json.JsonException e) {
            return Result.failure(PasskeysCreateFailureReason.REQUEST_MISSING_PARAMS);
        }

        var validatePasskeysCreateRequestResult =
                validatePasskeysCreateRequest(passkeysCreateRequest);
        if (validatePasskeysCreateRequestResult.isFailure()) {
            return validatePasskeysCreateRequestResult;
        }

        var publicSubjectId = input.getPathParameters().get("publicSubjectId");
        if (publicSubjectId.isEmpty()) {
            LOG.error("Request does not include public subject id");
            return Result.failure(PasskeysCreateFailureReason.REQUEST_MISSING_PARAMS);
        }

        boolean passkeyCreated;
        try {
            passkeyCreated =
                    dynamoPasskeyService.savePasskeyIfUnique(
                            publicSubjectId,
                            passkeysCreateRequest.getPasskeyId(),
                            passkeysCreateRequest.getAaguid(),
                            true,
                            0,
                            List.of("SomeTransport"),
                            true,
                            false);
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
        } else if (passkeysCreateRequest.getCredential().isEmpty()) {
            return Result.failure(PasskeysCreateFailureReason.INVALID_CREDENTIAL);
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
